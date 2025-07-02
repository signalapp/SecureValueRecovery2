// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db4.h"

#include <algorithm>
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_hash_sha256.h>
#include <string.h>

#include "env/env.h"
#include "sha/sha.h"
#include "util/log.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/constant.h"
#include "util/endian.h"
#include "context/context.h"
#include "metrics/metrics.h"
#include "proto/clientlog.pb.h"
#include "sip/hasher.h"
#include "ristretto/ristretto.h"

namespace svr2::db {

namespace {

void UpdateErrorCounters(client::Response4::Status s) {
  switch (s) {
    case client::Response4::UNSET:
      COUNTER(db4, client_err_UNSET)->Increment();
      break;
    case client::Response4::OK:
      COUNTER(db4, client_err_OK)->Increment();
      break;
    case client::Response4::INVALID_REQUEST:
      COUNTER(db4, client_err_INVALID_REQUEST)->Increment();
      break;
    case client::Response4::MISSING:
      COUNTER(db4, client_err_MISSING)->Increment();
      break;
    case client::Response4::ERROR:
      COUNTER(db4, client_err_ERROR)->Increment();
      break;
    case client::Response4::RESTORE1_MISSING:
      COUNTER(db4, client_err_RESTORE1_MISSING)->Increment();
      break;
    case client::Response4::VERSION_MISMATCH:
      COUNTER(db4, client_err_VERSION_MISMATCH)->Increment();
      break;
    case client::Response4::NOT_ROTATING:
      COUNTER(db4, client_err_NOT_ROTATING)->Increment();
      break;
    case client::Response4::ALREADY_ROTATING:
      COUNTER(db4, client_err_ALREADY_ROTATING)->Increment();
      break;
    case client::Response4::MERKLE_FAILURE:
      COUNTER(db4, client_err_MERKLE_FAILURE)->Increment();
      break;
    default:
      COUNTER(db4, client_err_UNKNOWN)->Increment();
      break;
  }
}

}  // namespace

const DB4::Protocol db4_protocol;

DB::Request* DB4::Protocol::RequestPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Request4>();
}

DB::Log* DB4::Protocol::LogPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Log4>();
}

std::pair<const DB::Log*, error::Error> DB4::ClientState::LogFromRequest(
    context::Context* ctx,
    const Request& request) {
  auto r = dynamic_cast<const client::Request4*>(&request);
  if (r == nullptr) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB4_RequestInvalid));
  }
  if (authenticated_id().size() != sizeof(BackupID)) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB4_BackupIDSize));
  }
  switch (r->inner_case()) {
    case client::Request4::kCreate:
    case client::Request4::kRestore1:
    case client::Request4::kRemove:
    case client::Request4::kQuery:
    case client::Request4::kRotateStart:
    case client::Request4::kRotateCommit:
    case client::Request4::kRotateRollback:
      // error checked in ValidateClientLog.
      break;
    default:
      return std::make_pair(nullptr, COUNTED_ERROR(DB4_LogRequestType));
  }
  auto log = ctx->Protobuf<client::Log4>();
  log->set_backup_id(authenticated_id());
  log->mutable_req()->MergeFrom(*r);
  return std::make_pair(log, error::OK);
}

std::pair<const DB::Response*, error::Error> DB4::ClientState::ResponseFromRequest(
    context::Context* ctx,
    const DB::Request& req) {
  auto r = dynamic_cast<const client::Request4*>(&req);
  if (r == nullptr) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB4_RequestInvalid));
  }
  std::unique_ptr<client::Effect4::Restore2State> restore2_client_state;
  {
    // Pull out restore2 client state.  It will either be used by this (the
    // request subsequent to the one that set the state) or cleared.
    util::unique_lock lock(mu_);
    restore2_client_state = std::move(restore2_);
  }
  ristretto::Point check_p;
  ristretto::Scalar check_s;
  switch (r->inner_case()) {
    case client::Request4::kRestore2: {
      COUNTER(db4, ops_restore2)->Increment();
      if (authenticated_id().size() != sizeof(BackupID)) {
        return std::make_pair(nullptr, COUNTED_ERROR(DB4_BackupIDSize));
      }
      auto resp = ctx->Protobuf<client::Response4>();
      auto r2 = resp->mutable_restore2();
      if (!restore2_client_state) {
        r2->set_status(client::Response4::RESTORE1_MISSING);
      } else if (
          !check_s.FromString(r->restore2().auth_scalar()) ||
          !check_p.FromString(r->restore2().auth_point())) {
        r2->set_status(client::Response4::INVALID_REQUEST);
      } else {
        BackupID id;
        CHECK(error::OK == util::StringIntoByteArray(authenticated_id(), &id));
        Restore2(ctx, id, r->restore2(), restore2_client_state.get(), r2, handshake_hash());
      }
      UpdateErrorCounters(resp->restore2().status());
      return std::make_pair(resp, error::OK);
    }
    default:
      // Only Restore2 is handled within this function; all other
      // operations are handled by ResponseFromEffect.  Returning
      // (null, OK) here signals that we should continue on to that.
      return std::make_pair(nullptr, error::OK);
  }
}

const DB::Response* DB4::ClientState::ResponseFromEffect(
    context::Context* ctx,
    const DB::Effect& effect) {
  auto e = dynamic_cast<const client::Effect4*>(&effect);
  if (e == nullptr) {
    return nullptr;
  }
  auto resp = &e->resp();
  if (resp->inner_case() == client::Response4::kRestore1 &&
      resp->restore1().status() == client::Response4::OK) {
    auto restore2 = std::make_unique<client::Effect4::Restore2State>();
    restore2->MergeFrom(dynamic_cast<const client::Effect4*>(&effect)->restore2_client_state());
    util::unique_lock lock(mu_);
    restore2_ = std::move(restore2);
  }
  return resp;
}

const std::string& DB4::Protocol::LogKey(const DB::Log& req) const {
  auto r = dynamic_cast<const client::Log4*>(&req);
  CHECK(r != nullptr);
  return r->backup_id();
}

error::Error DB4::Protocol::ValidateClientLog(const DB::Log& log_pb) const {
  auto log = dynamic_cast<const client::Log4*>(&log_pb);
  if (log == nullptr) { return COUNTED_ERROR(DB4_RequestInvalid); }
  if (log->backup_id().size() != sizeof(BackupID)) { return COUNTED_ERROR(DB4_BackupIDSize); }
  ristretto::Point check_p;
  ristretto::Scalar check_s;
  switch (log->req().inner_case()) {
    case client::Request4::kCreate: {
      const auto& req = log->req().create();
      if (req.max_tries() > MAX_ALLOWED_MAX_TRIES ||
          !check_p.FromString(req.auth_commitment()) ||
          !check_s.FromString(req.oprf_secretshare()) ||
          !check_s.FromString(req.zero_secretshare()) ||
          req.encryption_secretshare().size() != sizeof(AESKey) ||
          req.version() == 0) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRestore1: {
      const auto& req = log->req().restore1();
      if (!check_p.FromString(req.blinded())) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRemove:
      break;
    case client::Request4::kQuery: 
      break;
    case client::Request4::kRotateStart: {
      const auto& req = log->req().rotate_start();
      if (req.version() == 0 ||
          !check_s.FromString(req.oprf_secretshare_delta()) ||
          req.encryption_secretshare_delta().size() != sizeof(AESKey)) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRotateCommit: {
      const auto& req = log->req().rotate_commit();
      if (req.version() == 0) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRotateRollback: {
      const auto& req = log->req().rotate_rollback();
      if (req.version() == 0) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    default:
      return COUNTED_ERROR(DB4_ToplevelRequestType);
  }
  return error::OK;
}

std::unique_ptr<DB> DB4::Protocol::NewDB(merkle::Tree* t) const {
  return std::make_unique<DB4>(t);
}

const DB::Protocol* DB4::P() const {
  return &db4_protocol;
}

size_t DB4::Protocol::MaxRowSerializedSize() const {
  const size_t PROTOBUF_SMALL_STRING_EXTRA = 2;  // additional bytes for serializing string
  const size_t PROTOBUF_SMALL_INT = 2;           // bytes for serializing a small integer
  const size_t PROTOBUF_FIXED64 = 9;
  static const DB4::Row* row = nullptr;
  return sizeof(BackupID) + PROTOBUF_SMALL_STRING_EXTRA +
         PROTOBUF_SMALL_INT +  // tries
         sizeof(row->auth_commitment) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->oprf_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->encryption_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->zero_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->oprf_secretshare_delta) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->encryption_secretshare_delta) + PROTOBUF_SMALL_STRING_EXTRA +
         PROTOBUF_FIXED64 +  // version
         PROTOBUF_FIXED64 +  // new_version
         0;
}

DB::Effect* DB4::Run(context::Context* ctx, const DB::Log& log_pb) {
  MEASURE_CPU(ctx, cpu_db_client_request);
  CHECK(P()->ValidateClientLog(log_pb) == error::OK);
  auto log = dynamic_cast<const client::Log4*>(&log_pb);
  CHECK(log != nullptr);
  auto out = ctx->Protobuf<client::Effect4>();
  auto [id, err] = util::StringToByteArray<sizeof(BackupID)>(log->backup_id());
  CHECK(err == error::OK);
  switch (log->req().inner_case()) {
    case client::Request4::kCreate: {
      COUNTER(db4, ops_create)->Increment();
      Create(ctx, id, log->req().create(), out->mutable_resp()->mutable_create());
      UpdateErrorCounters(out->resp().create().status());
    } break;
    case client::Request4::kRestore1: {
      COUNTER(db4, ops_restore1)->Increment();
      Restore1(
          ctx, id, log->req().restore1(),
          out->mutable_resp()->mutable_restore1(),
          out->mutable_restore2_client_state());
      UpdateErrorCounters(out->resp().restore1().status());
      if (out->resp().restore1().status() != client::Response4::OK) {
        out->clear_restore2_client_state();
      }
    } break;
    case client::Request4::kRemove: {
      COUNTER(db4, ops_remove)->Increment();
      Remove(ctx, id, log->req().remove(), out->mutable_resp()->mutable_remove());
      // Remove doesn't actually return a status, but it'd make our counters
      // weird if we didn't have the same number of requests and error
      // codes, so just count an "OK".
      UpdateErrorCounters(client::Response4::OK);
    } break;
    case client::Request4::kQuery: {
      COUNTER(db4, ops_query)->Increment();
      Query(ctx, id, log->req().query(), out->mutable_resp()->mutable_query());
      UpdateErrorCounters(out->resp().query().status());
    } break;
    case client::Request4::kRotateStart: {
      COUNTER(db4, ops_rotate_start)->Increment();
      RotateStart(ctx, id, log->req().rotate_start(), out->mutable_resp()->mutable_rotate_start());
      UpdateErrorCounters(out->resp().rotate_start().status());
    } break;
    case client::Request4::kRotateCommit: {
      COUNTER(db4, ops_rotate_commit)->Increment();
      RotateCommit(ctx, id, log->req().rotate_commit(), out->mutable_resp()->mutable_rotate_commit());
      UpdateErrorCounters(out->resp().rotate_commit().status());
    } break;
    case client::Request4::kRotateRollback: {
      COUNTER(db4, ops_rotate_rollback)->Increment();
      RotateRollback(ctx, id, log->req().rotate_rollback(), out->mutable_resp()->mutable_rotate_rollback());
      UpdateErrorCounters(out->resp().rotate_rollback().status());
    } break;
    default: CHECK(nullptr == "should never reach here, client log already validated");
  }
  return out;
}

std::pair<std::string, error::Error> DB4::RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const {
  MEASURE_CPU(ctx, cpu_db_repl_send);
  auto iter = rows_.begin();
  BackupID id;
  if (!exclusive_start.empty()) {
    if (auto err = util::StringIntoByteArray(exclusive_start, &id); err != error::OK) {
      return std::make_pair("", err);
    }
    iter = rows_.upper_bound(id);
  }
  auto row = ctx->Protobuf<e2e::DB4RowState>();
  for (size_t i = 0; i < size && iter != rows_.end(); i++, ++iter) {
    row->Clear();
    row->set_backup_id(util::ByteArrayToString(iter->first));
    row->set_version(iter->second.version);
    row->set_tries(iter->second.tries);
    row->set_oprf_secretshare(iter->second.oprf_secretshare.ToString());
    row->set_auth_commitment(iter->second.auth_commitment.ToString());
    row->set_encryption_secretshare(util::ByteArrayToString(iter->second.encryption_secretshare));
    row->set_zero_secretshare(iter->second.zero_secretshare.ToString());
    if (iter->second.new_version) {
      row->set_oprf_secretshare_delta(iter->second.oprf_secretshare_delta.ToString());
      row->set_encryption_secretshare_delta(util::ByteArrayToString(iter->second.encryption_secretshare_delta));
      row->set_new_version(iter->second.new_version);
    }
    if (!row->SerializeToString(out->Add())) {
      return std::make_pair("", COUNTED_ERROR(DB4_ReplicationInvalidRow));
    }
  }
  LOG(DEBUG) << "DB sending rows in (" << util::PrefixToHex(exclusive_start, 8) << ", " << util::PrefixToHex(row->backup_id(), 8) << "]";
  return std::make_pair(row->backup_id(), error::OK);
}

std::pair<std::string, error::Error> DB4::LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows) {
  MEASURE_CPU(ctx, cpu_db_repl_recv);
  size_t initial_rows = rows_.size();
  auto row = ctx->Protobuf<e2e::DB4RowState>();
  for (int i = 0; i < rows.size(); i++) {
    row->Clear();
    if (!row->ParseFromString(rows.Get(i))) {
      return std::make_pair("", COUNTED_ERROR(DB4_ReplicationInvalidRow));
    }
    if (row->tries() > MAX_ALLOWED_MAX_TRIES ||
        row->tries() < 1) {
      return std::make_pair("", COUNTED_ERROR(DB4_ReplicationInvalidRow));
    }
    BackupID key;
    if (auto err = util::StringIntoByteArray(row->backup_id(), &key); err != error::OK) {
      return std::make_pair("", err);
    }
    if (rows_.size() && key <= rows_.rbegin()->first) {
      return std::make_pair("", COUNTED_ERROR(DB4_ReplicationOutOfOrder));
    }

    Row r(merkle_tree_);
    r.tries = row->tries();
    r.version = row->version();
    if (!r.auth_commitment.FromString(row->auth_commitment()) ||
        !r.oprf_secretshare.FromString(row->oprf_secretshare()) ||
        !r.zero_secretshare.FromString(row->zero_secretshare()) ||
        error::OK != util::StringIntoByteArray(row->encryption_secretshare(), &r.encryption_secretshare)) {
      return std::make_pair("", COUNTED_ERROR(DB4_ReplicationInvalidRow));
    }
    if (row->new_version()) {
      if (!r.oprf_secretshare_delta.FromString(row->oprf_secretshare_delta()) ||
          error::OK != util::StringIntoByteArray(row->encryption_secretshare_delta(), &r.encryption_secretshare_delta)) {
        return std::make_pair("", COUNTED_ERROR(DB4_ReplicationInvalidRow));
      }
      r.new_version = row->new_version();
    }
    merkle::Hash h;
    {
      MEASURE_CPU(ctx, cpu_db_repl_merkle_hash);
      h = merkle::HashFrom(HashRow(key, r));
    }
    {
      MEASURE_CPU(ctx, cpu_db_repl_merkle_update);
      r.merkle_leaf_.Update(h);
    }
    rows_.emplace_hint(rows_.end(), key, std::move(r));
    GAUGE(db, rows)->Set(rows_.size());
  }
  if (rows_.size() != initial_rows + rows.size()) {
    // This ensures that we didn't accidentally attempt to load rows that
    // already exist within the DB.
    return std::make_pair("", COUNTED_ERROR(DB4_LoadedRowsAlreadyInDB));
  }
  return std::make_pair(row->backup_id(), error::OK);
}

std::array<uint8_t, 16> DB4::HashRow(const BackupID& id, const Row& row) {
  std::array<uint8_t,
      sizeof(BackupID) +
      sizeof(row.auth_commitment) +
      sizeof(row.oprf_secretshare) +
      sizeof(row.encryption_secretshare) +
      sizeof(row.zero_secretshare) +
      sizeof(row.oprf_secretshare_delta) +
      sizeof(row.encryption_secretshare_delta) +
      1 +  // tries
      sizeof(row.version) +
      sizeof(row.new_version) +
      0> scratch = {0};
  size_t offset = 0;

#define FILL_SCRATCH(x) { \
  CHECK(offset + sizeof(x) <= scratch.size()); \
  memcpy(scratch.data() + offset, reinterpret_cast<const uint8_t*>(&x), sizeof(x)); \
  offset += sizeof(x); \
}
  FILL_SCRATCH(id);
  FILL_SCRATCH(row.auth_commitment);
  FILL_SCRATCH(row.oprf_secretshare);
  FILL_SCRATCH(row.encryption_secretshare);
  FILL_SCRATCH(row.zero_secretshare);
  FILL_SCRATCH(row.oprf_secretshare_delta);
  FILL_SCRATCH(row.encryption_secretshare_delta);
  FILL_SCRATCH(row.tries);
#undef FILL_SCRATCH
  CHECK(offset + 4 <= scratch.size());
  util::BigEndian32Bytes(row.version, scratch.data() + offset);
  offset += 4;
  CHECK(offset + 4 <= scratch.size());
  util::BigEndian32Bytes(row.new_version, scratch.data() + offset);
  offset += 4;

  CHECK(offset == scratch.size());

  return sip::FullZero.Hash16(scratch.data(), scratch.size());
}


std::array<uint8_t, 32> DB4::Hash(context::Context* ctx) const {
  MEASURE_CPU(ctx, cpu_db_hash);
  crypto_hash_sha256_state sha;
  crypto_hash_sha256_init(&sha);
  uint8_t num[8];
  util::BigEndian64Bytes(rows_.size(), num);
  crypto_hash_sha256_update(&sha, num, sizeof(num));
  for (auto iter = rows_.cbegin(); iter != rows_.cend(); ++iter) {
    auto row_hash = HashRow(iter->first, iter->second);
    crypto_hash_sha256_update(&sha, row_hash.data(), row_hash.size());
  }
  std::array<uint8_t, 32> out;
  crypto_hash_sha256_final(&sha, out.data());
  return out;
}

void DB4::Create(
    context::Context* ctx,
    const DB4::BackupID& id,
    const client::Request4::Create& req,
    client::Response4::Create* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    if (req.max_tries() == 0) {
      resp->set_status(client::Response4::INVALID_REQUEST);
      return;
    }
    auto e = rows_.emplace(id, merkle_tree_);
    find = e.first;
    GAUGE(db, rows)->Set(rows_.size());
  }
  Row* r = &find->second;

  // If max_tries is zero, use the previous tries rather than resetting.
  if (req.max_tries()) {
    r->tries = (uint8_t) req.max_tries();
  }
  r->version = req.version();
  CHECK(r->auth_commitment.FromString(req.auth_commitment()));
  CHECK(r->oprf_secretshare.FromString(req.oprf_secretshare()));
  CHECK(r->zero_secretshare.FromString(req.zero_secretshare()));
  CHECK(error::OK == util::StringIntoByteArray(req.encryption_secretshare(), &r->encryption_secretshare));
  // Reset any stored deltas.
  r->oprf_secretshare_delta.Clear();
  memset(r->encryption_secretshare_delta.data(), 0, sizeof(r->encryption_secretshare_delta));
  r->new_version = 0;

  r->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *r)));
  resp->set_status(client::Response4::OK);
  resp->set_tries_remaining(r->tries);
}

void DB4::Restore1(
    context::Context* ctx,
    const DB4::BackupID& id,
    const client::Request4::Restore1& req,
    client::Response4::Restore1* resp,
    client::Effect4::Restore2State* state) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::MISSING);
    return;
  }
  Row* row = &find->second;
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response4::MERKLE_FAILURE);
    LOG(ERROR) << "Error in verifying Merkle root during Restore1: " << err;
    return;
  }
  row->tries--;
  resp->set_tries_remaining(row->tries);
  resp->set_status(client::Response4::ERROR);

  ristretto::Point ristretto_hash;
  ristretto::Point blinded;
  ristretto::Point blinded_prime;
  ristretto::Point mask;
  ristretto::Point evaluated1;
  ristretto::Point evaluated2;
  if (!ristretto_hash.FromHash(sha::Sha512(id, req.blinded()))) {
    goto restore1_error;
  }
  if (!blinded.FromString(req.blinded())) {
    goto restore1_error;
  }

  if (!blinded.ScalarMult(row->oprf_secretshare, &blinded_prime)) {
    goto restore1_error;
  }
  if (!ristretto_hash.ScalarMult(row->zero_secretshare, &mask)) {
    goto restore1_error;
  }
  if (!blinded_prime.Add(mask, &evaluated1)) {
    goto restore1_error;
  }

  if (row->new_version != 0) {
    auto sum = row->oprf_secretshare.Add(row->oprf_secretshare_delta);
    ristretto::Point blinded_prime;
    ristretto::Point mask;
    if (!blinded.ScalarMult(sum, &blinded_prime)) {
      goto restore1_error;
    }
    if (!ristretto_hash.ScalarMult(row->zero_secretshare, &mask)) {
      goto restore1_error;
    }
    if (!blinded_prime.Add(mask, &evaluated2)) {
      goto restore1_error;
    }
    auto new_secretshare = row->encryption_secretshare;
    for (size_t i = 0; i < sizeof(row->encryption_secretshare); i++) {
      new_secretshare[i] ^= row->encryption_secretshare_delta[i];
    }
    state->set_new_encryption_secretshare(util::ByteArrayToString(new_secretshare));
    state->set_new_version(row->new_version);
  }

  resp->set_status(client::Response4::OK);
  state->set_version(row->version);
  state->set_auth_commitment(row->auth_commitment.ToString());
  state->set_encryption_secretshare(util::ByteArrayToString(row->encryption_secretshare));
  state->set_blinded_point(req.blinded());

  // Set the response auth element(s):
  {
    auto auth1 = resp->add_auth();
    auth1->set_element(evaluated1.ToString());
    auth1->set_version(row->version);
  }
  if (row->new_version) {
    auto auth2 = resp->add_auth();
    auth2->set_element(evaluated2.ToString());
    auth2->set_version(row->new_version);
  }
restore1_error:
  if (row->tries == 0) {
    COUNTER(db, guess_limit_reached)->Increment();
    rows_.erase(find);
    row = nullptr;  // The `row` ptr is no longer valid due to the `erase` call.
    GAUGE(db, rows)->Set(rows_.size());
  } else {
    row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  }
}

void DB4::ClientState::Restore2(
    context::Context* ctx,
    const BackupID& id,
    const client::Request4::Restore2& req,
    const client::Effect4::Restore2State* state,
    client::Response4::Restore2* resp,
    std::array<uint8_t,32> handshake_hash) const {
  ristretto::Point lhs1;
  resp->set_status(client::Response4::ERROR);
  ristretto::Scalar auth_scalar;
  if (!auth_scalar.FromString(req.auth_scalar())) {
    return;
  }
  if (!lhs1.ScalarMultBase(auth_scalar)) {
    return;
  }


  ristretto::Scalar scalar_hash = ristretto::Scalar::Reduce(sha::Sha512(req.auth_point(), state->blinded_point(), handshake_hash));

  ristretto::Point auth_commitment;
  if (!auth_commitment.FromString(state->auth_commitment())) {
    return;
  }
  ristretto::Point rhs1;
  if (!auth_commitment.ScalarMult(scalar_hash, &rhs1)) {
    return;
  }

  ristretto::Point auth_point;
  if (!auth_point.FromString(req.auth_point())) {
    return;
  }
  ristretto::Point rhs2;
  if (!auth_point.Add(rhs1, &rhs2)) {
    return;
  }

  if (!util::ConstantTimeEquals(lhs1, rhs2)) {
    return;
  }

  if (req.version() == state->version()) {
    resp->set_status(client::Response4::OK);
    resp->set_encryption_secretshare(state->encryption_secretshare());
  } else if (req.version() == state->new_version()) {
    resp->set_status(client::Response4::OK);
    resp->set_encryption_secretshare(state->new_encryption_secretshare());
  }
}

void DB4::Remove(
    context::Context* ctx,
    const DB4::BackupID& id,
    const client::Request4::Remove& req,
    client::Response4::Remove* resp) {
  auto find = rows_.find(id);
  if (find != rows_.end()) {
    // This calls the destructor of row.merkle_leaf_, updating the merkle tree.
    rows_.erase(find);
    GAUGE(db, rows)->Set(rows_.size());
  }
}

void DB4::Query(
    context::Context* ctx,
    const BackupID& id,
    const client::Request4::Query& request,
    client::Response4::Query* resp) const {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::MISSING);
    return;
  }
  const Row* row = &find->second;
  resp->set_status(client::Response4::OK);
  resp->set_tries_remaining(row->tries);
  resp->set_version(row->version);
  if (row->new_version) resp->set_new_version(row->new_version);
}

void DB4::RotateStart(
    context::Context* ctx,
    const BackupID& id,
    const client::Request4::RotateStart& req,
    client::Response4::RotateStart* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::MISSING);
    return;
  }
  Row* row = &find->second;
  if (row->new_version) {
    resp->set_status(client::Response4::ALREADY_ROTATING);
    return;
  } else if (req.version() == row->version) {
    resp->set_status(client::Response4::DUPLICATE_VERSION);
    return;
  }
  ristretto::Scalar oprf;
  // Checked in ValidateClientLog.
  CHECK(oprf.FromString(req.oprf_secretshare_delta()));
  AESKey enc;
  // Checked in ValidateClientLog.
  CHECK(error::OK == util::StringIntoByteArray(req.encryption_secretshare_delta(), &enc));
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response4::MERKLE_FAILURE);
    LOG(ERROR) << "Error in verifying Merkle root during RotateStart: " << err;
    return;
  }
  row->oprf_secretshare_delta = oprf;
  row->encryption_secretshare_delta = enc;
  row->new_version = req.version();
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::Response4::OK);
}

void DB4::RotateCommit(
    context::Context* ctx,
    const BackupID& id,
    const client::Request4::RotateCommit& req,
    client::Response4::RotateCommit* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::MISSING);
    return;
  }
  Row* row = &find->second;
  if (!row->new_version) {
    resp->set_status(client::Response4::NOT_ROTATING);
    return;
  } else if (row->new_version != req.version()) {
    resp->set_status(client::Response4::VERSION_MISMATCH);
    return;
  }
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response4::MERKLE_FAILURE);
    LOG(ERROR) << "Error in verifying Merkle root during RotateCommit: " << err;
    return;
  }
  row->oprf_secretshare = row->oprf_secretshare.Add(row->oprf_secretshare_delta);
  for (size_t i = 0; i < sizeof(row->encryption_secretshare); i++) {
    row->encryption_secretshare[i] ^= row->encryption_secretshare_delta[i];
  }
  row->oprf_secretshare_delta.Clear();
  row->encryption_secretshare_delta = {0};
  row->version = row->new_version;
  row->new_version = 0;
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::Response4::OK);
}

void DB4::RotateRollback(
    context::Context* ctx,
    const BackupID& id,
    const client::Request4::RotateRollback& req,
    client::Response4::RotateRollback* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::MISSING);
    return;
  }
  Row* row = &find->second;
  if (!row->new_version) {
    resp->set_status(client::Response4::NOT_ROTATING);
    return;
  } else if (row->new_version != req.version()) {
    resp->set_status(client::Response4::VERSION_MISMATCH);
    return;
  }
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response4::MERKLE_FAILURE);
    LOG(ERROR) << "Error in verifying Merkle root during RotateRollback: " << err;
    return;
  }
  row->oprf_secretshare_delta.Clear();
  row->encryption_secretshare_delta = {0};
  row->new_version = 0;
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::Response4::OK);
}

DB4::Row::Row(merkle::Tree* t) : version(0), new_version(0), encryption_secretshare{0}, encryption_secretshare_delta{0}, tries(0), merkle_leaf_(t) {}

DB4::Row::Row(DB4::Row&& other) :
    version(other.version),
    new_version(other.new_version),
    auth_commitment(other.auth_commitment),
    oprf_secretshare(other.oprf_secretshare),
    encryption_secretshare(other.encryption_secretshare),
    zero_secretshare(other.zero_secretshare),
    oprf_secretshare_delta(other.oprf_secretshare_delta),
    encryption_secretshare_delta(other.encryption_secretshare_delta),
    tries(other.tries),
    merkle_leaf_(std::move(other.merkle_leaf_)) {
  // When we move rows around in the database, we don't want to keep old
  // keys around.  So explicitly clear the old keys as part of the move.
  other.Clear();
}

DB4::Row::~Row() {
  // When remove rows from the database, we don't want to keep old
  // keys around.  So explicitly clear the old keys.
  Clear();
}

void DB4::Row::Clear() {
  version = 0;
  new_version = 0;
  util::MemZeroS(&auth_commitment, sizeof(auth_commitment));
  util::MemZeroS(&oprf_secretshare, sizeof(oprf_secretshare));
  util::MemZeroS(&encryption_secretshare, sizeof(encryption_secretshare));
  util::MemZeroS(&zero_secretshare, sizeof(zero_secretshare));
  util::MemZeroS(&oprf_secretshare_delta, sizeof(oprf_secretshare_delta));
  util::MemZeroS(&encryption_secretshare_delta, sizeof(encryption_secretshare_delta));
  tries = 0;
}

}  // namespace svr2::db
