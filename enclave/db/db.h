// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_DB_DB_H__
#define __SVR2_DB_DB_H__

#include <map>
#include <array>
#include <google/protobuf/message_lite.h>

#include "proto/error.pb.h"
#include "proto/e2e.pb.h"
#include "proto/msgs.pb.h"
#include "sip/hasher.h"
#include "context/context.h"
#include "util/log.h"
#include "merkle/merkle.h"

namespace svr2::db {

// DB provides a generic interface for databases, which can be used by both
// SVR2 (db2.*) and SVR3 (db3.*).  These two databases take in different
// requests and return different responses, which are packaged in the
// DB::Protocol interface and implemented per-database.
//
// A database uses three objects during its lifecycle:
//   - Request: a protobuf created and provided by a (remote) client
//   - Log: generated from a `Request` and contains the operation to be performed
//   - Respose: returned to the (remote) client detailing the output of the operation
//
// In many cases, the Request and Log will be similar, and often the Request
// is simply embedded into the Log.  However, the Log generally contains a
// few other key pieces of information:
//   - the database key associated with the request/authenticated_id, if there is one
//   - any information (entropy, timestamps, etc) which could differ if recomputed
//     across different replicas.
//
// Generally, the lifecycle of a request is:
//   - the Request is received by one replica
//   - that replica uses it to generate a Log
//   - that Log is submitted to Raft for ordering and persistence
//   - Raft commits the Log
//   - the Log is then applied to the database via the Run method
//   - the Run method generates a Response
//   - on the replica that received the Request, the Response is returned to the client
class DB {
 public:
  DELETE_COPY_AND_ASSIGN(DB);
  DB() {}
  virtual ~DB() {}

  typedef google::protobuf::MessageLite Request;
  typedef google::protobuf::MessageLite Log;
  typedef google::protobuf::MessageLite Response;

  // Protocol encapsulates typing requests and responses for clients.
  class Protocol {
   public:
    // RequestPB creates a new request protobuf in the scope of `ctx`
    virtual Request* RequestPB(context::Context* ctx) const = 0;
    // LogPB creates a new log protobuf in the scope of `ctx`
    virtual Log* LogPB(context::Context* ctx) const = 0;
    // Given a request, creates a log.  Note that this potentially std::move's
    // the request into the log, so care should be taken to not use the request
    // after calling LogPBFromRequest.
    virtual std::pair<Log*, error::Error> LogPBFromRequest(
        context::Context* ctx,
        Request&& request,
        const std::string& authenticated_id) const = 0;
    // LogKey returns the database key associated with the given request proto.
    virtual const std::string& LogKey(const Log& r) const = 0;
    // Validate that a log has the right shape, size, etc.
    virtual error::Error ValidateClientLog(const Log& log) const = 0;
    // Returns the maximum size of a database row when serialized.
    virtual size_t MaxRowSerializedSize() const = 0;
    virtual std::unique_ptr<DB> NewDB(merkle::Tree* t) const = 0;
  };
  // P() returns a pointer to a _static_ Protocol object,
  // which will outlast the DB object.
  virtual const Protocol* P() const = 0;
  // Returns a database protocol based on the passed-in version number.
  static const DB::Protocol* P(enclaveconfig::DatabaseVersion version);

  // Run a client log request and yield a response.
  // The client log should already have been checked with ValidateClientLog;
  // failing to do so will CHECK-fail.
  // It's assumed that validation happens on Raft log insert, so that
  // outputs from the Raft log are already validated.
  //
  // Output response is valid within the passed-in context.
  virtual Response* Run(context::Context* ctx, const Log& log) = 0;

  // Get rows from this database in range (exclusive_start, ...], returning
  // no more than [size] rows.  If it returns <[size] rows, the end of the database
  // has been reached.  Pass in empty string to start with the first key in
  // the database.  Returns the key of the largest returned row.
  virtual std::pair<std::string, error::Error> RowsAsProtos(
      context::Context* ctx,
      const std::string& exclusive_start,
      size_t size,
      google::protobuf::RepeatedPtrField<std::string>* out) const = 0;
  // Update this database using the given database row states.
  // This will return an error if any of the DatabaseRowStates contain
  // rows that already exist within the database.  Rows must be lexigraphically
  // larger than any existing row in the database.  Returns the row key
  // of the last row inserted into the database, on success.
  virtual std::pair<std::string, error::Error> LoadRowsFromProtos(
      context::Context* ctx,
      const google::protobuf::RepeatedPtrField<std::string>& rows) = 0;

  // Compute a hash of the entire database.  This is not designed to
  // be useful for security-focussed integrity checking, but should be
  // sufficient to verify that replicated data matches up between source
  // and destination.
  virtual std::array<uint8_t, 32> Hash(context::Context* ctx) const = 0;

  // Get the number of backups stored in the database
  virtual size_t row_count() const = 0;
};

}  // namespace svr2::db

#endif  // __SVR2_DB_DB_H__
