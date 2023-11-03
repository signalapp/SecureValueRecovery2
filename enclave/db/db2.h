// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_DB_DB2_H__
#define __SVR2_DB_DB2_H__

#include <map>
#include <array>
#include "proto/error.pb.h"
#include "proto/e2e.pb.h"
#include "sip/hasher.h"
#include "context/context.h"
#include "util/log.h"
#include "db/db.h"
#include "proto/client.pb.h"
#include "merkle/merkle.h"

namespace svr2::db {

// DB2 implements the DB interface for SVR2.
// DB is a database meant to be driven by a Raft log.
// Raft stores an ordered, consistent list of committed client::Request requests.
// This DB executes those requests as CRUD operations on an underlying ordered map,
// and returns their respective responses.
class DB2 : public DB {
 public:
  DELETE_COPY_AND_ASSIGN(DB2);
  DB2(merkle::Tree* t) : merkle_tree_(t) {}
  virtual ~DB2() {}

  class Protocol : public DB::Protocol {
   public:
    virtual Request* RequestPB(context::Context* ctx) const;
    virtual Log* LogPB(context::Context* ctx) const;
    virtual std::pair<Log*, error::Error> LogPBFromRequest(
        context::Context* ctx,
        Request&& request,
        const std::string& authenticated_id) const;
    virtual const std::string& LogKey(const Log& r) const;
    virtual error::Error ValidateClientLog(const Log& log) const;
    virtual size_t MaxRowSerializedSize() const;
    virtual std::unique_ptr<DB> NewDB(merkle::Tree* t) const;
  };
  virtual const DB::Protocol* P() const;

  // Run a client log request and yield a response.
  // The client log should already have been checked with ValidateClientLog;
  // failing to do so will CHECK-fail.
  // It's assumed that validation happens on Raft log insert, so that
  // outputs from the Raft log are already validated.
  //
  // Output response is valid within the passed-in context.
  virtual Response* Run(context::Context* ctx, const Log& request);

  // Limits on sizes/etc for validation.
  static const size_t BACKUP_ID_SIZE = 16;
  static const size_t MIN_DATA_SIZE = 16;
  static const size_t MAX_DATA_SIZE = 48;
  static const size_t PIN_SIZE = 32;
  static const uint16_t MAX_ALLOWED_MAX_TRIES = 255;
  static const uint16_t MIN_ALLOWED_MAX_TRIES = 1;

  // Get rows from this database in range (exclusive_start, ...], returning
  // no more than [size] rows.  If it returns <[size] rows, the end of the database
  // has been reached.  Pass in DB::Beginning to start with the first key in
  // the database.
  virtual std::pair<std::string, error::Error> RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const;
  // Update this database using the given database row states.
  // This will return an error if any of the DB2RowStates contain
  // rows that already exist within the database.  Rows must be lexigraphically
  // larger than any existing row in the database.  Returns the row key
  // of the last row inserted into the database, on success.
  virtual std::pair<std::string, error::Error> LoadRowsFromProtos(context::Context* ctx, const google::protobuf::RepeatedPtrField<std::string>& rows);

  // Compute a hash of the entire database.  This is not designed to
  // be useful for security-focussed integrity checking, but should be
  // sufficient to verify that replicated data matches up between source
  // and destination.
  virtual std::array<uint8_t, 32> Hash(context::Context* ctx) const;

  // Get the number of backups stored in the database
  virtual size_t row_count() const { return rows_.size(); }
 private:
  typedef std::array<uint8_t, BACKUP_ID_SIZE> BackupID;

  static std::pair<BackupID, error::Error> BackupIDFromString(const std::string& s);
  struct Row {
    Row(merkle::Tree* t);
    e2e::DB2RowState::State state;
    uint8_t tries;
    uint8_t data_size;  // should be MIN_DATA_SIZE <= data_size <= MAX_DATA_SIZE, or 0 if unset
    // We use std::array here to avoid lots of extra heap allocations.
    // We store slightly more data than necessary if client data is 
    // smaller than MAX_DATA_SIZE, but we make up for it in at least
    // three 64-bit pointers if these were std::string.
    std::array<uint8_t, MAX_DATA_SIZE> data;
    std::array<uint8_t, PIN_SIZE> pin;
    merkle::Leaf merkle_leaf_;

    void Clear(e2e::DB2RowState::State s);
  };
  static std::array<uint8_t, 16> HashRow(const BackupID& id, const Row& row);

  // Execute each of the three request types.
  void Backup(const BackupID& id, const client::BackupRequest& request, client::BackupResponse* resp);
  void Restore(const BackupID& id, const client::RestoreRequest& request, client::RestoreResponse* resp);
  void Delete(const BackupID& id, const client::DeleteRequest& request, client::DeleteResponse* resp);
  void Expose(const BackupID& id, const client::ExposeRequest& request, client::ExposeResponse* resp);
  void Tries(const BackupID& id, const client::TriesRequest& request, client::TriesResponse* resp) const;
  // We use std::map over std::unordered_map because order matters to us.
  // We need a consistently ordered keyspace for data transfers between
  // replicas.
  merkle::Tree* merkle_tree_;
  std::map<BackupID, Row> rows_;
};

extern const DB2::Protocol db2_protocol;

}  // namespace svr2::db

#endif  // __SVR2_DB_DB2_H__
