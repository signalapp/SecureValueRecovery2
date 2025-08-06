// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_DB_DB5_H__
#define __SVR2_DB_DB5_H__

#include <map>
#include <array>
#include "proto/error.pb.h"
#include "proto/e2e.pb.h"
#include "sip/hasher.h"
#include "context/context.h"
#include "util/log.h"
#include "db/db.h"
#include "proto/client5.pb.h"
#include "merkle/merkle.h"

namespace svr2::db {

// DB5 implements the DB interface for SVR2.
// DB is a database meant to be driven by a Raft log.
// Raft stores an ordered, consistent list of committed client::Request5 requests.
// This DB executes those requests as CRUD operations on an underlying ordered map,
// and returns their respective responses.
class DB5 : public DB {
 public:
  DELETE_COPY_AND_ASSIGN(DB5);
  DB5(merkle::Tree* t) : merkle_tree_(t) {}
  virtual ~DB5() {}

  class ClientState : public DB::ClientState {
   public:
    DELETE_COPY_AND_ASSIGN(ClientState);
    ClientState(ClientState&& move) = default;
    ClientState(const std::string& authenticated_id) : DB::ClientState(authenticated_id) {}
    virtual ~ClientState() {}
    // LogFromRequest is called if ResponseFromRequest returns null, and it
    // returns a Raft log entry to be presented to Raft for application.
    virtual std::pair<const Log*, error::Error> LogFromRequest (context::Context* ctx, const Request& req);
  };
  class Protocol : public DB::Protocol {
   public:
    virtual Request* RequestPB(context::Context* ctx) const;
    virtual Log* LogPB(context::Context* ctx) const;
    virtual const std::string& LogKey(const Log& r) const;
    virtual error::Error ValidateClientLog(const Log& log) const;
    virtual size_t MaxRowSerializedSize() const;
    virtual std::unique_ptr<DB> NewDB(merkle::Tree* t) const;
    virtual std::unique_ptr<DB::ClientState> NewClientState(const std::string& authenticated_id) const {
      return std::make_unique<ClientState>(authenticated_id);
    }
  };
  virtual const DB::Protocol* P() const;

  // Run a client log request and yield a response.
  // The client log should already have been checked with ValidateClientLog;
  // failing to do so will CHECK-fail.
  // It's assumed that validation happens on Raft log insert, so that
  // outputs from the Raft log are already validated.
  //
  // Output response is valid within the passed-in context.
  virtual Effect* Run(context::Context* ctx, const Log& request);

  // Limits on sizes/etc for validation.
  static const size_t BACKUP_ID_SIZE = 16;
  static const size_t DATA_SIZE = 32;
  static const size_t PASSWORD_SIZE = 32;

  // Get rows from this database in range (exclusive_start, ...], returning
  // no more than [size] rows.  If it returns <[size] rows, the end of the database
  // has been reached.  Pass in DB::Beginning to start with the first key in
  // the database.
  virtual std::pair<std::string, error::Error> RowsAsProtos(context::Context* ctx, const std::string& exclusive_start, size_t size, google::protobuf::RepeatedPtrField<std::string>* out) const;
  // Update this database using the given database row states.
  // This will return an error if any of the DB5RowStates contain
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
    ~Row();
    Row(Row&& other);
    Row(const Row&) = delete;
    std::array<uint8_t, DATA_SIZE> data;
    merkle::Leaf merkle_leaf_;
    void Clear();
  };
  static std::array<uint8_t, 16> HashRow(const BackupID& id, const Row& row);

  // Execute each of the three request types.
  void Download(const BackupID& id, const client::Request5::Download& request, client::Response5::Download* resp);
  void Upload(const BackupID& id, const client::Request5::Upload& request, client::Response5::Upload* resp);
  void Purge(const BackupID& id, const client::Request5::Purge& request, client::Response5::Purge* resp);
  // We use std::map over std::unordered_map because order matters to us.
  // We need a consistently ordered keyspace for data transfers between
  // replicas.
  merkle::Tree* merkle_tree_;
  std::map<BackupID, Row> rows_;
};

extern const DB5::Protocol db5_protocol;

}  // namespace svr2::db

#endif  // __SVR2_DB_DB5_H__
