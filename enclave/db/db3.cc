// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db3.h"

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

namespace svr2::db {

DB::Request* DB3::Protocol::RequestPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Request3>();
}

DB::Log* DB3::Protocol::LogPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Log3>();
}

std::pair<DB::Log*, error::Error> DB3::Protocol::LogPBFromRequest(
    context::Context* ctx,
    Request&& request,
    const std::string& authenticated_id) const {
  auto r = dynamic_cast<client::Request3*>(&request);
  if (r == nullptr) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB3_RequestInvalid));
  }
  if (authenticated_id.size() != BACKUP_ID_SIZE) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB3_BackupIDSize));
  }
  auto log = ctx->Protobuf<client::Log3>();
  log->set_backup_id(authenticated_id);
  *log->mutable_req() = std::move(*r);
  if (log->req().inner_case() == client::Request3::kCreate) {
    MEASURE_CPU(ctx, cpu_db3_new_keys);
    auto priv = NewKey();
    log->set_create_privkey(util::ByteArrayToString(priv));
  }
  return std::make_pair(log, error::OK);
}

const std::string& DB3::Protocol::LogKey(const DB::Log& req) const {
  auto r = dynamic_cast<const client::Log3*>(&req);
  CHECK(r != nullptr);
  return r->backup_id();
}

error::Error DB3::Protocol::ValidateClientLog(const DB::Log& log_pb) const {
  auto log = dynamic_cast<const client::Log3*>(&log_pb);
  if (log == nullptr) { return COUNTED_ERROR(DB3_RequestInvalid); }
  if (log->backup_id().size() != BACKUP_ID_SIZE) { return COUNTED_ERROR(DB3_BackupIDSize); }
  switch (log->req().inner_case()) {
    case client::Request3::kCreate: {
      auto r = log->req().create();
      if (r.max_tries() < 1 || r.max_tries() > 255) { return COUNTED_ERROR(DB3_MaxTriesOutOfRange); }
      if (r.blinded_element().size() != ELEMENT_SIZE) { return COUNTED_ERROR(DB3_BlindedElementSize); }
      if (log->create_privkey().size() != sizeof(PrivateKey)) { return COUNTED_ERROR(DB3_LogPrivateKeyInvalid); }
    } break;
    case client::Request3::kEvaluate: {
      auto r = log->req().evaluate();
      if (r.blinded_element().size() != ELEMENT_SIZE) { return COUNTED_ERROR(DB3_BlindedElementSize); }
    } break;
    case client::Request3::kQuery: 
    case client::Request3::kRemove: {
      // nothing to do
    } break;
    default:
      return COUNTED_ERROR(DB3_ToplevelRequestType);
  }
  return error::OK;
}

const DB::Protocol* DB3::P() const {
  static DB3::Protocol rr;
  return &rr;
}

size_t DB3::Protocol::MaxRowSerializedSize() const {
  const size_t PROTOBUF_SMALL_STRING_EXTRA = 2;  // additional bytes for serializing string
  const size_t PROTOBUF_SMALL_INT = 2;           // bytes for serializing a small integer
  return BACKUP_ID_SIZE + PROTOBUF_SMALL_STRING_EXTRA +  // backup ID
      SCALAR_SIZE + PROTOBUF_SMALL_STRING_EXTRA +        // priv key
      PROTOBUF_SMALL_INT;                                // tries
}

DB::Response* DB3::Run(context::Context* ctx, const DB::Log& log_pb) {
  MEASURE_CPU(ctx, cpu_db_client_request);
  CHECK(P()->ValidateClientLog(log_pb) == error::OK);
  auto log = dynamic_cast<const client::Log3*>(&log_pb);
  CHECK(log != nullptr);
  auto out = ctx->Protobuf<client::Response3>();
  auto [id, err] = util::StringToByteArray<BACKUP_ID_SIZE>(log->backup_id());
  CHECK(err == error::OK);
  switch (log->req().inner_case()) {
    case client::Request3::kCreate: {
      COUNTER(db3, ops_create)->Increment();
      Create(ctx, id, log->create_privkey(), log->req().create(), out->mutable_create());
    } break;
    case client::Request3::kEvaluate: {
      COUNTER(db3, ops_evaluate)->Increment();
      Evaluate(ctx, id, log->req().evaluate(), out->mutable_evaluate());
    } break;
    case client::Request3::kRemove: {
      COUNTER(db3, ops_remove)->Increment();
      Remove(ctx, id, log->req().remove(), out->mutable_remove());
    } break;
    case client::Request3::kQuery: {
      COUNTER(db3, ops_query)->Increment();
      Query(ctx, id, log->req().query(), out->mutable_query());
    } break;
    default: CHECK(nullptr == "should never reach here, client log already validated");
  }
  return out;
}

std::pair<std::string, error::Error> DB3::RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const {
  MEASURE_CPU(ctx, cpu_db_repl_send);
  auto iter = rows_.begin();
  if (!exclusive_start.empty()) {
    auto [id, err] = util::StringToByteArray<BACKUP_ID_SIZE>(exclusive_start);
    if (err != error::OK) {
      return std::make_pair("", err);
    }
    iter = rows_.upper_bound(id);
  }
  auto row = ctx->Protobuf<e2e::DB3RowState>();
  for (size_t i = 0; i < size && iter != rows_.end(); i++, ++iter) {
    row->Clear();
    row->set_backup_id(util::ByteArrayToString(iter->first));
    row->set_priv(util::ByteArrayToString(iter->second.priv));
    row->set_tries(iter->second.tries);
    if (!row->SerializeToString(out->Add())) {
      return std::make_pair("", COUNTED_ERROR(DB3_ReplicationInvalidRow));
    }
  }
  LOG(DEBUG) << "DB sending rows in (" << util::PrefixToHex(exclusive_start, 8) << ", " << util::PrefixToHex(row->backup_id(), 8) << "]";
  return std::make_pair(row->backup_id(), error::OK);
}

std::pair<std::string, error::Error> DB3::LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows) {
  MEASURE_CPU(ctx, cpu_db_repl_recv);
  size_t initial_rows = rows_.size();
  auto row = ctx->Protobuf<e2e::DB3RowState>();
  for (int i = 0; i < rows.size(); i++) {
    row->Clear();
    if (!row->ParseFromString(rows.Get(i))) {
      return std::make_pair("", COUNTED_ERROR(DB3_ReplicationInvalidRow));
    }
    if (row->tries() > MAX_ALLOWED_MAX_TRIES ||
        row->tries() < MIN_ALLOWED_MAX_TRIES) {
      return std::make_pair("", COUNTED_ERROR(DB3_ReplicationInvalidRow));
    }
    auto [key, err1] = util::StringToByteArray<BACKUP_ID_SIZE>(row->backup_id());
    if (err1 != error::OK) {
      return std::make_pair("", err1);
    }
    if (rows_.size() && key <= rows_.rbegin()->first) {
      return std::make_pair("", COUNTED_ERROR(DB3_ReplicationOutOfOrder));
    }
    auto [priv, err2] = util::StringToByteArray<sizeof(PrivateKey)>(row->priv());
    if (err2 != error::OK) {
      return std::make_pair("", err2);
    }

    Row r;
    r.tries = row->tries();
    r.priv = priv;
    rows_.emplace_hint(rows_.end(), key, std::move(r));
    GAUGE(db, rows)->Set(rows_.size());
  }
  if (rows_.size() != initial_rows + rows.size()) {
    // This ensures that we didn't accidentally attempt to load rows that
    // already exist within the DB.
    return std::make_pair("", COUNTED_ERROR(DB3_LoadedRowsAlreadyInDB));
  }
  return std::make_pair(row->backup_id(), error::OK);
}

std::array<uint8_t, 32> DB3::Hash(context::Context* ctx) const {
  MEASURE_CPU(ctx, cpu_db_hash);
  crypto_hash_sha256_state sha;
  crypto_hash_sha256_init(&sha);
  uint8_t num[8];
  util::BigEndian64Bytes(rows_.size(), num);
  crypto_hash_sha256_update(&sha, num, sizeof(num));
  for (auto iter = rows_.cbegin(); iter != rows_.cend(); ++iter) {
    crypto_hash_sha256_update(&sha, iter->first.data(), iter->first.size());
    util::BigEndian64Bytes(iter->second.tries, num);
    crypto_hash_sha256_update(&sha, num, sizeof(num));
    crypto_hash_sha256_update(&sha, iter->second.priv.data(), iter->second.priv.size());
  }
  std::array<uint8_t, 32> out;
  crypto_hash_sha256_final(&sha, out.data());
  return out;
}

std::pair<DB3::Element, error::Error> DB3::BlindEvaluate(
    context::Context* ctx,
    const DB3::PrivateKey& key,
    const DB3::Element& blinded_element) {
  MEASURE_CPU(ctx, cpu_db3_blind_evaluate);
  Element out{0};
  int ret = 0;
  if (0 != (ret = crypto_scalarmult_ristretto255(out.data(), key.data(), blinded_element.data()))) {
    LOG(WARNING) << "crypto_scalarmult_ristretto255 error: " << ret;
    return std::make_pair(out, COUNTED_ERROR(DB3_ScalarMultFailure));
  }
  return std::make_pair(out, error::OK);
}

DB3::PrivateKey DB3::Protocol::NewKey() {
  PrivateKey priv{0};
  crypto_core_ristretto255_scalar_random(priv.data());
  return priv;
}

void DB3::Create(
    context::Context* ctx,
    const DB3::BackupID& id,
    const std::string& privkey,
    const client::CreateRequest& req,
    client::CreateResponse* resp) {
  auto [elt, err1] = util::StringToByteArray<ELEMENT_SIZE>(req.blinded_element());
  if (err1 != error::OK) {
    resp->set_status(client::CreateResponse::INVALID_REQUEST);
    return;
  }
  auto [priv, err2] = util::StringToByteArray<sizeof(PrivateKey)>(privkey);
  if (err2 != error::OK) {
    resp->set_status(client::CreateResponse::ERROR);
    return;
  }
  auto [evaluated, err3] = BlindEvaluate(ctx, priv, elt);
  if (err3 != error::OK) {
    resp->set_status(client::CreateResponse::ERROR);
    return;
  }
  rows_[id] = {
    .priv = priv,
    .tries = (uint8_t) req.max_tries(),
  };
  GAUGE(db, rows)->Set(rows_.size());
  resp->set_evaluated_element(util::ByteArrayToString(evaluated));
  resp->set_status(client::CreateResponse::OK);
}

void DB3::Evaluate(
    context::Context* ctx,
    const DB3::BackupID& id,
    const client::EvaluateRequest& req,
    client::EvaluateResponse* resp) {
  auto [elt, err1] = util::StringToByteArray<ELEMENT_SIZE>(req.blinded_element());
  if (err1 != error::OK) {
    resp->set_status(client::EvaluateResponse::INVALID_REQUEST);
    return;
  }
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::EvaluateResponse::MISSING);
    return;
  }
  auto [evaluated, err2] = BlindEvaluate(ctx, find->second.priv, elt);
  if (err2 != error::OK) {
    resp->set_status(client::EvaluateResponse::ERROR);
    return;
  }
  find->second.tries--;
  resp->set_tries_remaining(find->second.tries);
  if (find->second.tries == 0) {
    rows_.erase(find);
    GAUGE(db, rows)->Set(rows_.size());
  }
  resp->set_evaluated_element(util::ByteArrayToString(evaluated));
  resp->set_status(client::EvaluateResponse::OK);
}

void DB3::Remove(
    context::Context* ctx,
    const DB3::BackupID& id,
    const client::RemoveRequest& req,
    client::RemoveResponse* resp) {
  auto find = rows_.find(id);
  if (find != rows_.end()) {
    rows_.erase(find);
    GAUGE(db, rows)->Set(rows_.size());
  }
}

void DB3::Query(
    context::Context* ctx,
    const BackupID& id,
    const client::QueryRequest& request,
    client::QueryResponse* resp) const {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::QueryResponse::MISSING);
    return;
  }
  const Row* row = &find->second;
  resp->set_status(client::QueryResponse::OK);
  resp->set_tries_remaining(row->tries);
}

}  // namespace svr2::db
