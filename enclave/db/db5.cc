// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db5.h"

#include <algorithm>
#include <sodium/crypto_auth_hmacsha256.h>

#include "util/log.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/constant.h"
#include "util/endian.h"
#include "context/context.h"
#include "metrics/metrics.h"
#include "proto/clientlog.pb.h"
#include "sip/hasher.h"
#include "hmac/hmac.h"

namespace svr2::db {

const DB5::Protocol db5_protocol;

template <class T>
static void CopyArrayToString(const T& array, std::string* out) {
  CHECK(array.size() == 0 || sizeof(array[0]) == 1);
  out->resize(array.size());
  std::copy(array.cbegin(), array.cend(), out->begin());
}

static size_t SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA = 2;
size_t DB5::Protocol::MaxRowSerializedSize() const {
  return
    BACKUP_ID_SIZE + SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA +
    DATA_SIZE + SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA;
}

DB::Request* DB5::Protocol::RequestPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Request5>();
}

DB::Log* DB5::Protocol::LogPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Log5>();
}

std::pair<const DB::Log*, error::Error> DB5::ClientState::LogFromRequest(
    context::Context* ctx,
    const Request& request) {
  auto r = dynamic_cast<const client::Request5*>(&request);
  if (r == nullptr) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB5_InvalidRequestType));
  }
  auto log = ctx->Protobuf<client::Log5>();
  if (authenticated_id().size() != BACKUP_ID_SIZE) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB5_ClientBackupIDSize));
  }
  log->set_backup_id(authenticated_id());
  log->mutable_req()->MergeFrom(*r);
  return std::make_pair(log, error::OK);
}

const std::string& DB5::Protocol::LogKey(const DB::Log& req) const {
  auto r = dynamic_cast<const client::Log5*>(&req);
  CHECK(r != nullptr);
  return r->backup_id();
}

error::Error DB5::Protocol::ValidateClientLog(const DB::Log& req_pb) const {
  auto log = dynamic_cast<const client::Log5*>(&req_pb);
  if (log == nullptr) { return COUNTED_ERROR(DB5_InvalidRequestType); }
  auto req = log->req();
  
  if (log->backup_id().size() != BACKUP_ID_SIZE) { return COUNTED_ERROR(DB5_ClientBackupIDSize); }
  switch (req.inner_case()) {
    case client::Request5::kUpload: {
      auto r = req.upload();
      if (r.data().size() != DATA_SIZE) { return COUNTED_ERROR(DB5_ClientDataSize); }
    } break;
    case client::Request5::kDownload: {
      auto r = req.download();
      if (r.password().size() != PASSWORD_SIZE) { return COUNTED_ERROR(DB5_ClientPasswordSize); }
    } break;
    case client::Request5::kPurge:
      // nothing to do for these
      break;
    default:
      return COUNTED_ERROR(DB5_ClientRequestCase);
  }
  return error::OK;
}

std::unique_ptr<DB> DB5::Protocol::NewDB(merkle::Tree* t) const {
  return std::make_unique<DB5>(t);
}

const DB::Protocol* DB5::P() const {
  return &db5_protocol;
}

DB::Effect* DB5::Run(context::Context* ctx, const DB::Log& log_pb) {
  // We CHECK here because this should have already been validated when it
  // was added to the Raft log.
  MEASURE_CPU(ctx, cpu_db_client_request);
  CHECK(error::OK == P()->ValidateClientLog(log_pb));
  auto log = reinterpret_cast<const client::Log5&>(log_pb);  // dynamic_cast checked in ValidateClientLog.
  BackupID id;
  CHECK(log.backup_id().size() == id.size());
  std::copy(log.backup_id().begin(), log.backup_id().end(), id.begin());
  auto resp = ctx->Protobuf<client::Response5>();
  switch (log.req().inner_case()) {
    case client::Request5::kUpload:
      COUNTER(db5, ops_upload)->Increment();
      Upload(id, log.req().upload(), resp->mutable_upload());
      break;
    case client::Request5::kDownload:
      COUNTER(db5, ops_download)->Increment();
      Download(id, log.req().download(), resp->mutable_download());
      break;
    case client::Request5::kPurge:
      COUNTER(db5, ops_purge)->Increment();
      Purge(id, log.req().purge(), resp->mutable_purge());
      break;
    default:
      COUNTER(db5, ops_unknown)->Increment();
      LOG(WARNING) << "unsupported request case, returning empty response";
      break;
  }
  return resp;
}

void DB5::Upload(const BackupID& id, const client::Request5::Upload& req, client::Response5::Upload* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    auto e = rows_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(std::move(id)),
        std::forward_as_tuple(merkle_tree_));
    find = e.first;
    GAUGE(db, rows)->Set(rows_.size());
  }
  Row* row = &find->second;
  std::copy(req.data().begin(), req.data().end(), row->data.begin());
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::Response5::OK);
}

void DB5::Download(const BackupID& id, const client::Request5::Download& req, client::Response5::Download* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::Response5::MISSING);
    return;
  }
  Row* row = &find->second;
  // First, check that our DB is still valid w.r.t. this row.
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::Response5::MERKLE_FAILURE);
    LOG(ERROR) << "Error in verifying Merkle root during Download: " << err;
    return;
  }

  auto out = hmac::HmacSha256(row->data, req.password());
  CopyArrayToString(out, resp->mutable_output());
  resp->set_status(client::Response5::OK);
}

void DB5::Purge(const BackupID& id, const client::Request5::Purge& req, client::Response5::Purge* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) { return; }
  rows_.erase(find);
  GAUGE(db, rows)->Set(rows_.size());
}

std::pair<std::string, error::Error> DB5::RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const {
  MEASURE_CPU(ctx, cpu_db_repl_send);
  auto iter = rows_.begin();
  if (!exclusive_start.empty()) {
    auto [id, err] = BackupIDFromString(exclusive_start);
    if (err != error::OK) {
      return std::make_pair("", err);
    }
    iter = rows_.upper_bound(id);
  }
  auto row = ctx->Protobuf<e2e::DB5RowState>();
  std::string last_id;
  for (size_t i = 0; i < size && iter != rows_.end(); i++, ++iter) {
    row->Clear();
    CopyArrayToString(iter->first, row->mutable_backup_id());
    CopyArrayToString(iter->second.data, row->mutable_data());
    if (!row->SerializeToString(out->Add())) {
      return std::make_pair("", COUNTED_ERROR(DB5_ReplicationInvalidRow));
    }
    last_id = row->backup_id();
  }
  LOG(DEBUG) << "DB sending rows in (" << util::PrefixToHex(exclusive_start, 8) << ", " << util::PrefixToHex(last_id, 8) << "]";
  return std::make_pair(last_id, error::OK);
}

DB5::Row::Row(merkle::Tree* t) : data{0}, merkle_leaf_(t) {}

void DB5::Row::Clear() {
  util::MemZeroS(&data, sizeof(data));
}

DB5::Row::~Row() {
  Clear();
}

DB5::Row::Row(DB5::Row&& orig) :
    merkle_leaf_(std::move(orig.merkle_leaf_)) {
  data = orig.data;
  // orig.Clear() will be called when its destructor is called.
}

std::pair<std::string, error::Error> DB5::LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows) {
  MEASURE_CPU(ctx, cpu_db_repl_recv);
  CHECK(rows.size());
  size_t initial_rows = rows_.size();
  auto row = ctx->Protobuf<e2e::DB5RowState>();
  for (int i = 0; i < rows.size(); i++) {
    row->Clear();
    if (!row->ParseFromString(rows.Get(i))) {
      return std::make_pair("", COUNTED_ERROR(DB5_ReplicationInvalidRow));
    }
    if (row->data().size() != DATA_SIZE) {
      return std::make_pair("", COUNTED_ERROR(DB5_ReplicationInvalidRow));
    }
    auto [key, err] = BackupIDFromString(row->backup_id());
    if (err != error::OK) {
      return std::make_pair("", err);
    }
    if (rows_.size() && key <= rows_.rbegin()->first) {
      return std::make_pair("", COUNTED_ERROR(DB5_ReplicationOutOfOrder));
    }

    Row r(merkle_tree_);
    std::copy(row->data().begin(), row->data().end(), r.data.begin());
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
    return std::make_pair("", COUNTED_ERROR(DB5_LoadedRowsAlreadyInDB));
  }
  return std::make_pair(row->backup_id(), error::OK);
}

std::pair<DB5::BackupID, error::Error> DB5::BackupIDFromString(const std::string& s) {
  DB5::BackupID out;
  if (s.size() != BACKUP_ID_SIZE) {
    return std::make_pair(std::move(out), COUNTED_ERROR(DB5_BackupIDSize));
  }
  std::copy(s.begin(), s.end(), out.data());
  return std::make_pair(std::move(out), error::OK);
}

std::array<uint8_t, 16> DB5::HashRow(const BackupID& id, const Row& row) {
  std::array<uint8_t,
      BACKUP_ID_SIZE +  // id
      DATA_SIZE  +  // data
      0> scratch = {0};
  size_t offset = 0;
  memcpy(scratch.data() + offset, id.data(), BACKUP_ID_SIZE);  offset += BACKUP_ID_SIZE;
  memcpy(scratch.data() + offset, row.data.data(), DATA_SIZE); offset += DATA_SIZE;
  CHECK(offset == scratch.size());

  return sip::FullZero.Hash16(scratch.data(), scratch.size());
}

std::array<uint8_t, 32> DB5::Hash(context::Context* ctx) const {
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

}  // namespace svr2::db
