// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db4.h"

#include <algorithm>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_core_ristretto255.h>

#include "util/log.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/constant.h"
#include "util/endian.h"
#include "context/context.h"
#include "metrics/metrics.h"
#include "proto/clientlog.pb.h"
#include "sip/hasher.h"

namespace svr2::db {

namespace {

template <class T>
const uint8_t* U8(const T& p) {
  return reinterpret_cast<const uint8_t*>(p.data());
}

template <class T>
bool ValidRistrettoPoint(const T& p) {
  if (p.size() != sizeof(DB4::RistrettoPoint)) {
    return false;
  }
  return crypto_core_ristretto255_is_valid_point(U8(p));
}

template <class T>
bool ValidRistrettoScalar(const T& s) {
  if (s.size() != sizeof(DB4::RistrettoScalar)) {
    return false;
  }
  // libsodium doesn't seem to have a "is this scalar already reduced"
  // call, so we instead resort to reducing and checking equality.
  auto data = U8(s);
  uint8_t nonreduced[crypto_core_ristretto255_NONREDUCEDSCALARBYTES] = {0};
  uint8_t reduced[sizeof(DB4::RistrettoScalar)] = {0};
  // Bytes are stored little-endian, so copy into the front of nonreduced.
  memcpy(nonreduced, data, sizeof(DB4::RistrettoScalar));
  crypto_core_ristretto255_scalar_reduce(reduced, nonreduced);
  return util::ConstantTimeEqualsBytes(data, reduced, sizeof(DB4::RistrettoScalar));
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
  switch (r->inner_case()) {
    case client::Request4::kRestore2: {
      if (authenticated_id().size() != sizeof(BackupID)) {
        return std::make_pair(nullptr, COUNTED_ERROR(DB4_BackupIDSize));
      }
      auto resp = ctx->Protobuf<client::Response4>();
      auto r2 = resp->mutable_restore2();
      if (!restore2_client_state) {
        r2->set_status(client::Response4::Restore2::RESTORE1_MISSING);
      } else if (!ValidRistrettoScalar(r->restore2().auth_scalar()) ||
          !ValidRistrettoPoint(r->restore2().auth_point())) {
        r2->set_status(client::Response4::Restore2::INVALID_REQUEST);
      } else {
        BackupID id;
        CHECK(error::OK == util::StringIntoByteArray(authenticated_id(), &id));
        Restore2(ctx, id, r->restore2(), restore2_client_state.get(), r2);
      }
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
      resp->restore1().status() == client::Response4::Restore1::OK) {
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
  switch (log->req().inner_case()) {
    case client::Request4::kCreate: {
      const auto& req = log->req().create();
      if (req.max_tries() > MAX_ALLOWED_MAX_TRIES ||
          !ValidRistrettoPoint(req.auth_commitment()) ||
          !ValidRistrettoScalar(req.oprf_secretshare()) ||
          !ValidRistrettoScalar(req.zero_secretshare()) ||
          req.encryption_secretshare().size() != sizeof(AESKey)) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRestore1: {
      const auto& req = log->req().restore1();
      if (!ValidRistrettoPoint(req.blinded())) {
        return COUNTED_ERROR(DB4_RequestInvalid);
      }
    } break;
    case client::Request4::kRemove:
      return COUNTED_ERROR(General_Unimplemented);
    case client::Request4::kQuery: 
      return COUNTED_ERROR(General_Unimplemented);
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
  static const DB4::Row* row = nullptr;
  return sizeof(BackupID) + PROTOBUF_SMALL_STRING_EXTRA +
         PROTOBUF_SMALL_INT +  // tries
         sizeof(row->auth_commitment) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->oprf_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->encryption_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->zero_secretshare) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->oprf_secretshare_delta) + PROTOBUF_SMALL_STRING_EXTRA +
         sizeof(row->encryption_secretshare_delta) + PROTOBUF_SMALL_STRING_EXTRA +
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
    } break;
    case client::Request4::kRestore1: {
      COUNTER(db4, ops_restore1)->Increment();
      Restore1(
          ctx, id, log->req().restore1(),
          out->mutable_resp()->mutable_restore1(),
          out->mutable_restore2_client_state());
    } break;
    case client::Request4::kRemove: {
      COUNTER(db4, ops_remove)->Increment();
      Remove(ctx, id, log->req().remove(), out->mutable_resp()->mutable_remove());
    } break;
    case client::Request4::kQuery: {
      COUNTER(db4, ops_query)->Increment();
      Query(ctx, id, log->req().query(), out->mutable_resp()->mutable_query());
    } break;
    default: CHECK(nullptr == "should never reach here, client log already validated");
  }
  return out;
}

std::pair<std::string, error::Error> DB4::RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const {
  // TODO: this
  return std::make_pair("", error::General_Unimplemented);
}

std::pair<std::string, error::Error> DB4::LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows) {
  return std::make_pair("", error::General_Unimplemented);
}


std::array<uint8_t, 16> DB4::HashRow(const BackupID& id, const Row& row) {
  std::array<uint8_t,
      sizeof(BackupID) +
      sizeof(row.auth_commitment) +
      sizeof(row.oprf_secretshare) +
      sizeof(row.encryption_secretshare) +
      sizeof(row.zero_secretshare) +
      1 +  // has_delta
      sizeof(row.oprf_secretshare_delta) +
      sizeof(row.encryption_secretshare_delta) +
      1 +  // tries
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
  FILL_SCRATCH(row.has_delta);
  FILL_SCRATCH(row.oprf_secretshare_delta);
  FILL_SCRATCH(row.encryption_secretshare_delta);
  FILL_SCRATCH(row.tries);
#undef FILL_SCRATCH

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
      resp->set_status(client::Response4::Create::INVALID_REQUEST);
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
  CHECK(error::OK == util::StringIntoByteArray(req.auth_commitment(), &r->auth_commitment));
  CHECK(error::OK == util::StringIntoByteArray(req.oprf_secretshare(), &r->oprf_secretshare));
  CHECK(error::OK == util::StringIntoByteArray(req.encryption_secretshare(), &r->encryption_secretshare));
  CHECK(error::OK == util::StringIntoByteArray(req.zero_secretshare(), &r->zero_secretshare));
  // Reset any stored deltas.
  memset(r->oprf_secretshare_delta.data(), 0, sizeof(r->oprf_secretshare_delta));
  memset(r->encryption_secretshare_delta.data(), 0, sizeof(r->encryption_secretshare_delta));
  r->has_delta = 0;

  r->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *r)));
  resp->set_status(client::Response4::Create::OK);
}

void DB4::Restore1(
    context::Context* ctx,
    const DB4::BackupID& id,
    const client::Request4::Restore1& req,
    client::Response4::Restore1* resp,
    client::Effect4::Restore2State* state) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response4::Restore1::MISSING);
    return;
  }
  Row* row = &find->second;
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response4::Restore1::ERROR);
    LOG(ERROR) << "Error in verifying Merkle root during Evaluate: " << err;
    return;
  }
  row->tries--;
  resp->set_tries_remaining(row->tries);
  resp->set_status(client::Response4::Restore1::ERROR);

  RistrettoPoint blinded_prime;
  if (0 != crypto_scalarmult_ristretto255(
      blinded_prime.data(),
      row->oprf_secretshare.data(),
      U8(req.blinded()))) {
    goto restore1_error;
  }

  std::array<uint8_t, 64> sha512_hash;
  crypto_hash_sha512_state sha512_state;
  crypto_hash_sha512_init(&sha512_state);
  crypto_hash_sha512_update(&sha512_state, id.data(), sizeof(id));
  crypto_hash_sha512_update(&sha512_state, U8(req.blinded()), req.blinded().size());
  crypto_hash_sha512_final(&sha512_state, sha512_hash.data());

  RistrettoPoint ristretto_hash;
  crypto_core_ristretto255_from_hash(ristretto_hash.data(), sha512_hash.data());

  RistrettoPoint mask;
  if (0 != crypto_scalarmult_ristretto255(mask.data(), row->zero_secretshare.data(), ristretto_hash.data())) {
    goto restore1_error;
  }

  RistrettoPoint evaluated;
  if (0 != crypto_core_ristretto255_add(evaluated.data(), blinded_prime.data(), mask.data())) {
    goto restore1_error;
  }
  resp->set_element(util::ByteArrayToString(evaluated));
  resp->set_status(client::Response4::Restore1::OK);
  state->set_auth_commitment(util::ByteArrayToString(row->auth_commitment));
  state->set_encryption_secretshare(util::ByteArrayToString(row->encryption_secretshare));

restore1_error:
  if (row->tries == 0) {
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
    client::Response4::Restore2* resp) const {
  RistrettoPoint lhs1;
  resp->set_status(client::Response4::Restore2::ERROR);
  if (0 != crypto_scalarmult_ristretto255_base(lhs1.data(), U8(req.auth_scalar()))) {
    return;
  }
  std::array<uint8_t, 64> sha512_hash;
  crypto_hash_sha512_state sha512_state;
  crypto_hash_sha512_init(&sha512_state);
  crypto_hash_sha512_update(&sha512_state, U8(req.auth_point()), req.auth_point().size());
  crypto_hash_sha512_final(&sha512_state, sha512_hash.data());

  RistrettoScalar scalar_hash;
  crypto_core_ristretto255_scalar_reduce(scalar_hash.data(), sha512_hash.data());

  RistrettoPoint rhs1;
  if (0 != crypto_scalarmult_ristretto255(rhs1.data(), scalar_hash.data(), U8(state->auth_commitment()))) {
    return;
  }

  RistrettoPoint rhs2;
  if (0 != crypto_core_ristretto255_add(rhs2.data(), rhs1.data(), U8(req.auth_point()))) {
    return;
  }

  if (!util::ConstantTimeEquals(lhs1, rhs2)) {
    return;
  }

  resp->set_status(client::Response4::Restore2::OK);
  resp->set_encryption_secretshare(state->encryption_secretshare());
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
    resp->set_status(client::Response4::Query::MISSING);
    return;
  }
  const Row* row = &find->second;
  resp->set_status(client::Response4::Query::OK);
  resp->set_tries_remaining(row->tries);
}

DB4::Row::Row(merkle::Tree* t) : has_delta(0), tries(0), merkle_leaf_(t) {}

}  // namespace svr2::db
