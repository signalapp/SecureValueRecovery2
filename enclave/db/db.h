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
//   - if the client session's ClientState can, it generates a response and returns it immediately
//   - that replica uses it to generate a Log
//   - that Log is submitted to Raft for ordering and persistence
//   - Raft commits the Log
//   - the Log is then applied to the database via the Run method, creating an Effect
//   - if there is a client session associated with that log, the Effect is converted to a Response and returned to the client
class DB {
 public:
  DELETE_COPY_AND_ASSIGN(DB);
  DB() {}
  virtual ~DB() {}

  // A Request is a protobuf received from a client.
  typedef google::protobuf::MessageLite Request;
  // A Log is the protobuf that's added to the Raft log, generally encapsulating
  // the Request and any additional generated state that must agree across all
  // replicas (random numbers or timestamps that need to be generated, etc) to
  // make the request deterministic.
  typedef google::protobuf::MessageLite Log;
  // An Effect is the changes associated with a Log, and should at least encapsulate
  // enough information to craft a response to the client.  It may also contain
  // additional information utlizable by ClientState to serve potential subsequent
  // client requests.
  typedef google::protobuf::MessageLite Effect;
  // A Response is the protobuf that's returned to the client that initiated the
  // original Request.  This is the information that is able to leave the server.
  typedef google::protobuf::MessageLite Response;

  // ClientState represents the state of a single client session.
  // If a ClientState implementation utilizes its member variables
  // in order to actually serve state, it should utilize locking to
  // protect them.  While a well-behaved host process and client will
  // only ever access a single client sequentially, a malicious host
  // may attempt to corrupt state by accessing a single client in
  // parallel.
  class ClientState {
   public:
    ClientState(const std::string& authenticated_id) : authenticated_id_(authenticated_id) {}
    virtual ~ClientState() {}
    // ResponseFromRequest is called prior to a Request being translated into
    // a Log and applied to the Raft database.  If a non-null response
    // is returned from here, the Raft process is skipped and the response is
    // immediately returned to the client.  The default implementation
    // always returns null, thus always utilizing Raft.  An error returned
    // here will kill this client.
    virtual std::pair<const Response*, error::Error> ResponseFromRequest(context::Context* ctx, const Request& req) {
      return std::make_pair(nullptr, error::OK);
    }
    // LogFromRequest is called if ResponseFromRequest returns null, and it
    // returns a Raft log entry to be presented to Raft for application.
    virtual std::pair<const Log*, error::Error> LogFromRequest (context::Context* ctx, const Request& req) = 0;
    // ResponseFromEffect is called after a Request has been tranlated into
    // a Log and applied to the Raft database.  Returning a null response from
    // this function is erroneous.  The default implementation utilizes the
    // Effect as a Response and returns it unchanged.
    virtual const Response* ResponseFromEffect(context::Context* ctx, const Effect& effect) { return &effect; }

    // authenticated_id returns the authenticated identifier associated
    // with this client.
    const std::string& authenticated_id() const { return authenticated_id_; }

   private:
    const std::string authenticated_id_;
  };

  // The GLOBAL_KEY is used for logs that have a global effect on the
  // database, rather than an effect on a single row.
  static const std::string GLOBAL_KEY;

  // Protocol encapsulates typing requests and responses for clients.
  class Protocol {
   public:
    // RequestPB creates a new request protobuf in the scope of `ctx`
    virtual Request* RequestPB(context::Context* ctx) const = 0;
    // LogPB creates a new log protobuf in the scope of `ctx`
    virtual Log* LogPB(context::Context* ctx) const = 0;
    // LogKey returns the database key associated with the given request proto.
    virtual const std::string& LogKey(const Log& r) const = 0;
    // Validate that a log has the right shape, size, etc.
    virtual error::Error ValidateClientLog(const Log& log) const = 0;
    // Returns the maximum size of a database row when serialized.
    virtual size_t MaxRowSerializedSize() const = 0;
    // NewDB returns a new database associated with this protocol.
    virtual std::unique_ptr<DB> NewDB(merkle::Tree* t) const = 0;
    // Returns a new client state object associated with this database type.
    virtual std::unique_ptr<ClientState> NewClientState(const std::string& authenticated_id) const = 0;
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
  virtual Effect* Run(context::Context* ctx, const Log& log) = 0;

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
