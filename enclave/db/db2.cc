// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db2.h"

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
extern "C" {
#include "sip/siphash.h"
}  // extern "C"

namespace svr2::db {

const DB2::Protocol db2_protocol;

template <class T>
static void CopyArrayToString(const T& array, std::string* out) {
  CHECK(array.size() == 0 || sizeof(array[0]) == 1);
  out->resize(array.size());
  std::copy(array.cbegin(), array.cend(), out->begin());
}

static size_t SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA = 2;
static size_t U16_AS_VARINT_MAX_SIZE = 3;
size_t DB2::Protocol::MaxRowSerializedSize() const {
  return
    BACKUP_ID_SIZE + SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA +
    MAX_DATA_SIZE + SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA +
    PIN_SIZE + SMALL_BYTES_FIELD_EXTRA_PROTO_METADATA +
    U16_AS_VARINT_MAX_SIZE;  // max bytes for TRIES
}

DB::Request* DB2::Protocol::RequestPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Request>();
}

DB::Log* DB2::Protocol::LogPB(context::Context* ctx) const {
  return ctx->Protobuf<client::Log2>();
}

std::pair<DB::Log*, error::Error> DB2::Protocol::LogPBFromRequest(
        context::Context* ctx,
        Request&& request,
        const std::string& authenticated_id) const {
  auto r = dynamic_cast<client::Request*>(&request);
  if (r == nullptr) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB2_InvalidRequestType));
  }
  auto log = ctx->Protobuf<client::Log2>();
  if (authenticated_id.size() != BACKUP_ID_SIZE) {
    return std::make_pair(nullptr, COUNTED_ERROR(DB2_ClientBackupIDSize));
  }
  log->set_backup_id(authenticated_id);
  *log->mutable_req() = std::move(*r);
  return std::make_pair(log, error::OK);
}

const std::string& DB2::Protocol::LogKey(const DB::Log& req) const {
  auto r = dynamic_cast<const client::Log2*>(&req);
  CHECK(r != nullptr);
  return r->backup_id();
}

error::Error DB2::Protocol::ValidateClientLog(const DB::Log& req_pb) const {
  auto log = dynamic_cast<const client::Log2*>(&req_pb);
  if (log == nullptr) { return COUNTED_ERROR(DB2_InvalidRequestType); }
  auto req = log->req();
  
  if (log->backup_id().size() != BACKUP_ID_SIZE) { return COUNTED_ERROR(DB2_ClientBackupIDSize); }
  switch (req.inner_case()) {
    case client::Request::kBackup: {
      auto r = req.backup();
      if (r.pin().size() != PIN_SIZE) { return COUNTED_ERROR(DB2_ClientPinSize); }
      if (r.data().size() > MAX_DATA_SIZE) { return COUNTED_ERROR(DB2_ClientDataSize); }
      if (r.data().size() < MIN_DATA_SIZE) { return COUNTED_ERROR(DB2_ClientDataSize); }
      if (r.max_tries() > MAX_ALLOWED_MAX_TRIES) { return COUNTED_ERROR(DB2_ClientTriesTooHigh); }
      if (r.max_tries() < MIN_ALLOWED_MAX_TRIES) { return COUNTED_ERROR(DB2_ClientTriesZero); }
    } break;
    case client::Request::kRestore: {
      auto r = req.restore();
      if (r.pin().size() != PIN_SIZE) { return COUNTED_ERROR(DB2_ClientPinSize); }
    } break;
    case client::Request::kExpose: {
      auto r = req.expose();
      if (r.data().size() > MAX_DATA_SIZE) { return COUNTED_ERROR(DB2_ClientDataSize); }
      if (r.data().size() < MIN_DATA_SIZE) { return COUNTED_ERROR(DB2_ClientDataSize); }
    } break;
    case client::Request::kTries:
    case client::Request::kDelete:
      // nothing to do for these
      break;
    default:
      return COUNTED_ERROR(DB2_ClientRequestCase);
  }
  return error::OK;
}

std::unique_ptr<DB> DB2::Protocol::NewDB(merkle::Tree* t) const {
  return std::make_unique<DB2>(t);
}

const DB::Protocol* DB2::P() const {
  return &db2_protocol;
}

DB::Response* DB2::Run(context::Context* ctx, const DB::Log& log_pb) {
  // We CHECK here because this should have already been validated when it
  // was added to the Raft log.
  MEASURE_CPU(ctx, cpu_db_client_request);
  CHECK(error::OK == P()->ValidateClientLog(log_pb));
  auto log = reinterpret_cast<const client::Log2&>(log_pb);  // dynamic_cast checked in ValidateClientLog.
  BackupID id;
  CHECK(log.backup_id().size() == id.size());
  std::copy(log.backup_id().begin(), log.backup_id().end(), id.begin());
  auto resp = ctx->Protobuf<client::Response>();
  switch (log.req().inner_case()) {
    case client::Request::kBackup:
      COUNTER(db2, ops_backup)->Increment();
      Backup(id, log.req().backup(), resp->mutable_backup());
      break;
    case client::Request::kRestore:
      COUNTER(db2, ops_restore)->Increment();
      Restore(id, log.req().restore(), resp->mutable_restore());
      break;
    case client::Request::kDelete:
      COUNTER(db2, ops_delete)->Increment();
      Delete(id, log.req().delete_(), resp->mutable_delete_());
      break;
    case client::Request::kExpose:
      COUNTER(db2, ops_expose)->Increment();
      Expose(id, log.req().expose(), resp->mutable_expose());
      break;
    case client::Request::kTries:
      COUNTER(db2, ops_tries)->Increment();
      Tries(id, log.req().tries(), resp->mutable_tries());
      break;
    default:
      COUNTER(db2, ops_unknown)->Increment();
      LOG(WARNING) << "unsupported request case, returning empty response";
      break;
  }
  return resp;
}

void DB2::Row::Clear(e2e::DB2RowState::State s) {
  memset(data.begin(), 0, data.size());
  memset(pin.begin(), 0, pin.size());
  tries = 0;
  data_size = 0;
  state = s;
}

void DB2::Backup(const BackupID& id, const client::BackupRequest& req, client::BackupResponse* resp) {
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
  row->Clear(e2e::DB2RowState::POPULATED);
  std::copy(req.data().begin(), req.data().end(), row->data.begin());
  row->data_size = req.data().size();
  row->tries = req.max_tries();
  std::copy(req.pin().begin(), req.pin().end(), row->pin.begin());
  // We don't verify our merkle tree on backup, since it clears state.  We do update it, though.
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::BackupResponse::OK);
}

void DB2::Restore(const BackupID& id, const client::RestoreRequest& req, client::RestoreResponse* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end() || find->second.state != e2e::DB2RowState::AVAILABLE) {
    resp->set_status(client::RestoreResponse::MISSING);
    return;
  }
  Row* row = &find->second;
  // First, check that our DB is still valid w.r.t. this row.
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::RestoreResponse::ERROR);
    LOG(ERROR) << "Error in verifying Merkle root during Restore: " << err;
    return;
  }

  if (util::ConstantTimeEquals(req.pin(), row->pin)) {
    resp->set_status(client::RestoreResponse::OK);
    resp->set_tries(row->tries);
    *resp->mutable_data() = std::string(row->data.begin(), row->data.begin() + row->data_size);
    return;
  }
  if (--row->tries == 0) {
    // We Clear before erasing because erasing just removes the entry from the log, and
    // we want to actually zero out the secret wherever it is in memory.
    row->Clear(e2e::DB2RowState::UNINITIATED);
    // This removes the row, which also removes it from the Merkle tree.
    rows_.erase(find);
    resp->set_status(client::RestoreResponse::MISSING);
    GAUGE(db, rows)->Set(rows_.size());
    return;
  }
  // Update the Merkle tree with our new tries.
  row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
  resp->set_status(client::RestoreResponse::PIN_MISMATCH);
  resp->set_tries(row->tries);
}

void DB2::Delete(const BackupID& id, const client::DeleteRequest& req, client::DeleteResponse* resp) {
  auto find = rows_.find(id);
  if (find == rows_.end()) { return; }
  // We Clear before erasing because erasing just removes the entry from the log, and
  // we want to actually zero out the secret wherever it is in memory.
  find->second.Clear(e2e::DB2RowState::UNINITIATED);
  rows_.erase(find);
  GAUGE(db, rows)->Set(rows_.size());
}

void DB2::Expose(const BackupID& id, const client::ExposeRequest& req, client::ExposeResponse* resp) {
  // Expose provides a 2-phase commit of backups, to avoid client backup
  // retries from allowing server operators infinite guesses against the pin.
  // Without Expose, the following attack is possible:
  //   1. client sends BackupRequest
  //   2. server processes BackupRequest
  //   3. server operator drops connection to client before BackupResponse is sent
  //   4. server operator makes max_tries guesses against backup
  //   5. client retries BackupRequest (goto 1)
  //
  // The Expose proto must contain the secret to make sure that only someone
  // that already knows the secret (IE: the client) can expose the backup for
  // restores.  Otherwise, the following attack is possible:
  //   1. client sends BackupRequest
  //   2. server processes BackupRequest
  //   3. server operator drops connection to client before BackupResponse is sent
  //   4. server operator sends ExposeRequest to enclave, which processes it
  //   5. server operator makes max_tries guesses against backup
  //   6. client retries BackupRequest (goto 1)
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::ExposeResponse::ERROR);
    return;
  }
  Row* row = &find->second;
  // First, check that our DB is still valid w.r.t. this row.
  if (error::Error err = row->merkle_leaf_.Verify(merkle::HashFrom(HashRow(id, *row))); err != error::OK) {
    resp->set_status(client::ExposeResponse::ERROR);
    LOG(ERROR) << "Error in verifying Merkle root during Expose: " << err;
    return;
  }
  if (!util::ConstantTimeEqualsPrefix(row->data, req.data(), row->data_size)) {
    resp->set_status(client::ExposeResponse::ERROR);
    return;
  }
  switch (row->state) {
  case e2e::DB2RowState::POPULATED:
  case e2e::DB2RowState::AVAILABLE:
    row->state = e2e::DB2RowState::AVAILABLE;
    row->merkle_leaf_.Update(merkle::HashFrom(HashRow(id, *row)));
    resp->set_status(client::ExposeResponse::OK);
    return;
  default:
    resp->set_status(client::ExposeResponse::ERROR);
    return;
  }
}

void DB2::Tries(const BackupID& id, const client::TriesRequest& request, client::TriesResponse* resp) const {
  auto find = rows_.find(id);
  if (find == rows_.end()) {
    resp->set_status(client::TriesResponse::MISSING);
    return;
  }
  const Row* row = &find->second;
  resp->set_status(client::TriesResponse::OK);
  resp->set_exposed(row->state == e2e::DB2RowState::AVAILABLE);
  resp->set_tries(row->tries);
}

std::pair<std::string, error::Error> DB2::RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const {
  MEASURE_CPU(ctx, cpu_db_repl_send);
  auto iter = rows_.begin();
  if (!exclusive_start.empty()) {
    auto [id, err] = BackupIDFromString(exclusive_start);
    if (err != error::OK) {
      return std::make_pair("", err);
    }
    iter = rows_.upper_bound(id);
  }
  auto row = ctx->Protobuf<e2e::DB2RowState>();
  std::string last_id;
  for (size_t i = 0; i < size && iter != rows_.end(); i++, ++iter) {
    row->Clear();
    CopyArrayToString(iter->first, row->mutable_backup_id());
    CopyArrayToString(iter->second.data, row->mutable_data());
    row->mutable_data()->resize(iter->second.data_size);
    CopyArrayToString(iter->second.pin, row->mutable_pin());
    row->set_tries(iter->second.tries);
    row->set_state(iter->second.state);
    if (!row->SerializeToString(out->Add())) {
      return std::make_pair("", COUNTED_ERROR(DB2_ReplicationInvalidRow));
    }
    last_id = row->backup_id();
  }
  LOG(DEBUG) << "DB sending rows in (" << util::PrefixToHex(exclusive_start, 8) << ", " << util::PrefixToHex(last_id, 8) << "]";
  return std::make_pair(last_id, error::OK);
}

DB2::Row::Row(merkle::Tree* t) : state(e2e::DB2RowState::UNINITIATED), tries(0), data_size(0), data{0}, pin{0}, merkle_leaf_(t) {}

std::pair<std::string, error::Error> DB2::LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows) {
  MEASURE_CPU(ctx, cpu_db_repl_recv);
  CHECK(rows.size());
  size_t initial_rows = rows_.size();
  auto row = ctx->Protobuf<e2e::DB2RowState>();
  for (int i = 0; i < rows.size(); i++) {
    row->Clear();
    if (!row->ParseFromString(rows.Get(i))) {
      return std::make_pair("", COUNTED_ERROR(DB2_ReplicationInvalidRow));
    }
    if (row->tries() > MAX_ALLOWED_MAX_TRIES ||
        row->pin().size() != PIN_SIZE ||
        row->data().size() < MIN_DATA_SIZE ||
        row->data().size() > MAX_DATA_SIZE) {
      return std::make_pair("", COUNTED_ERROR(DB2_ReplicationInvalidRow));
    }
    auto [key, err] = BackupIDFromString(row->backup_id());
    if (err != error::OK) {
      return std::make_pair("", err);
    }
    if (rows_.size() && key <= rows_.rbegin()->first) {
      return std::make_pair("", COUNTED_ERROR(DB2_ReplicationOutOfOrder));
    }

    Row r(merkle_tree_);
    r.state = row->state();
    std::copy(row->pin().begin(), row->pin().end(), r.pin.begin());
    std::copy(row->data().begin(), row->data().end(), r.data.begin());
    r.data_size = row->data().size();
    r.tries = row->tries();
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
    return std::make_pair("", COUNTED_ERROR(DB2_LoadedRowsAlreadyInDB));
  }
  return std::make_pair(row->backup_id(), error::OK);
}

std::pair<DB2::BackupID, error::Error> DB2::BackupIDFromString(const std::string& s) {
  DB2::BackupID out;
  if (s.size() != BACKUP_ID_SIZE) {
    return std::make_pair(std::move(out), COUNTED_ERROR(DB2_BackupIDSize));
  }
  std::copy(s.begin(), s.end(), out.data());
  return std::make_pair(std::move(out), error::OK);
}

static std::array<uint8_t, 16> db2_sip_hash = {'S', 'V', 'R', 'd', 'b', '2', 0};

std::array<uint8_t, 16> DB2::HashRow(const BackupID& id, const Row& row) {
  std::array<uint8_t,
      BACKUP_ID_SIZE +  // id
      4              +  // state
      4              +  // tries
      4              +  // data_size
      MAX_DATA_SIZE  +  // data
      PIN_SIZE       +  // pin
      0> scratch = {0};
  size_t offset = 0;
  memcpy(scratch.data() + offset, id.data(), id.size());           offset += BACKUP_ID_SIZE;
  util::BigEndian32Bytes(row.state, scratch.data() + offset);      offset += 4;
  util::BigEndian32Bytes(row.tries, scratch.data() + offset);      offset += 4;
  util::BigEndian32Bytes(row.data_size, scratch.data() + offset);  offset += 4;
  memcpy(scratch.data() + offset, row.data.data(), row.data_size); offset += MAX_DATA_SIZE;
  memcpy(scratch.data() + offset, row.pin.data(), row.pin.size()); offset += PIN_SIZE;
  CHECK(offset == scratch.size());

  std::array<uint8_t, 16> out;
  siphash(
      scratch.data(), scratch.size(),
      db2_sip_hash.data(),  // must be constant to be comparable across replicas.
      out.data(), out.size());
  return out;
}

std::array<uint8_t, 32> DB2::Hash(context::Context* ctx) const {
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
