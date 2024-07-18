// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db4.h"

#include <algorithm>
#include <sodium/crypto_auth_hmacsha256.h>
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
  if (authenticated_id().size() != BACKUP_ID_SIZE) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB4_BackupIDSize));
  }
  switch (r->inner_case()) {
    case client::Request4::kCreate:
      break;
    case client::Request4::kRestore1:
      break;
    case client::Request4::kRemove:
      break;
    case client::Request4::kQuery:
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
  if (r->inner_case() != client::Request4::kRestore2) {
    return std::make_pair(nullptr, error::OK);
  }
  if (!restore2_client_state) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB4_Restore2StateMissing));
  }
  return std::make_pair(nullptr, error::General_Unimplemented);
}

const DB::Response* DB4::ClientState::ResponseFromEffect(
    context::Context* ctx,
    const DB::Effect& effect) {
  auto e = dynamic_cast<const client::Effect4*>(&effect);
  if (e == nullptr) {
    return nullptr;
  }
  if (e->resp().inner_case() == client::Response4::kRestore1 &&
      e->resp().restore1().status() == client::Response4::Restore1::OK) {
    auto restore2 = std::make_unique<client::Effect4::Restore2State>();
    // TODO: fill in restore2 client state.
    util::unique_lock lock(mu_);
    restore2_ = std::move(restore2);
  }
  return &e->resp();
}

const std::string& DB4::Protocol::LogKey(const DB::Log& req) const {
  auto r = dynamic_cast<const client::Log4*>(&req);
  CHECK(r != nullptr);
  return r->backup_id();
}

error::Error DB4::Protocol::ValidateClientLog(const DB::Log& log_pb) const {
  auto log = dynamic_cast<const client::Log4*>(&log_pb);
  if (log == nullptr) { return COUNTED_ERROR(DB4_RequestInvalid); }
  if (log->backup_id().size() != BACKUP_ID_SIZE) { return COUNTED_ERROR(DB4_BackupIDSize); }
  switch (log->req().inner_case()) {
    case client::Request4::kCreate:
      break;
    case client::Request4::kRestore1:
      break;
    case client::Request4::kRemove:
      break;
    case client::Request4::kQuery: 
      break;
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
  // TODO: update this as row is updated
  return BACKUP_ID_SIZE;
}

DB::Effect* DB4::Run(context::Context* ctx, const DB::Log& log_pb) {
  MEASURE_CPU(ctx, cpu_db_client_request);
  CHECK(P()->ValidateClientLog(log_pb) == error::OK);
  auto log = dynamic_cast<const client::Log4*>(&log_pb);
  CHECK(log != nullptr);
  auto out = ctx->Protobuf<client::Effect4>();
  auto [id, err] = util::StringToByteArray<BACKUP_ID_SIZE>(log->backup_id());
  CHECK(err == error::OK);
  switch (log->req().inner_case()) {
    case client::Request4::kCreate: {
      COUNTER(db4, ops_create)->Increment();
      Create(ctx, id, log->req().create(), out->mutable_resp()->mutable_create());
    } break;
    case client::Request4::kRestore1: {
      COUNTER(db4, ops_restore1)->Increment();
      Restore1(ctx, id, log->req().restore1(), out->mutable_resp()->mutable_restore1());
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
  // TODO: this
  std::array<uint8_t, BACKUP_ID_SIZE> scratch = {0}; // id
  size_t offset = 0;
  CHECK(id.size() == BACKUP_ID_SIZE);
  memcpy(scratch.data() + offset, id.data(), id.size());  offset += BACKUP_ID_SIZE;
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
    auto e = rows_.emplace(id, merkle_tree_);
    find = e.first;
    GAUGE(db, rows)->Set(rows_.size());
  }
  Row* r = &find->second;
  r->tries = (uint8_t) req.max_tries();
  r->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *r)));
  resp->set_status(client::Response4::Create::OK);
}

void DB4::Restore1(
    context::Context* ctx,
    const DB4::BackupID& id,
    const client::Request4::Restore1& req,
    client::Response4::Restore1* resp) {
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
  if (row->tries == 0) {
    rows_.erase(find);
    row = nullptr;  // The `row` ptr is no longer valid due to the `erase` call.
    GAUGE(db, rows)->Set(rows_.size());
  } else {
    row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  }
  resp->set_status(client::Response4::Restore1::OK);
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

DB4::Row::Row(merkle::Tree* t) : merkle_leaf_(t) {}

}  // namespace svr2::db
