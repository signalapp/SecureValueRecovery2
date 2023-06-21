// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_DB_DB3_H__
#define __SVR2_DB_DB3_H__

#include <map>
#include <array>
#include "proto/error.pb.h"
#include "proto/e2e.pb.h"
#include "proto/msgs.pb.h"
#include "sip/hasher.h"
#include "context/context.h"
#include "util/log.h"
#include "db/db.h"
#include "proto/client3.pb.h"
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>

namespace svr2::db {

class DB3 : public DB {
 public:
  DELETE_COPY_AND_ASSIGN(DB3);
  DB3() {}
  virtual ~DB3() {}

  static const size_t BACKUP_ID_SIZE = 16;
  static const size_t SCALAR_SIZE = crypto_scalarmult_ristretto255_SCALARBYTES;
  static const size_t ELEMENT_SIZE = crypto_scalarmult_ristretto255_BYTES;
  typedef std::array<uint8_t, BACKUP_ID_SIZE> BackupID;
  typedef std::array<uint8_t, SCALAR_SIZE> Scalar;
  typedef std::array<uint8_t, ELEMENT_SIZE> Element;
  typedef Scalar PrivateKey;
  typedef Element PublicKey;
  static const uint16_t MAX_ALLOWED_MAX_TRIES = 255;
  static const uint16_t MIN_ALLOWED_MAX_TRIES = 1;

  // Protocol encapsulates typing requests and responses for clients.
  class Protocol : public DB::Protocol {
   public:
    virtual DB::Request* RequestPB(context::Context* ctx) const;
    virtual DB::Log* LogPB(context::Context* ctx) const;
    virtual std::pair<Log*, error::Error> LogPBFromRequest(
        context::Context* ctx,
        Request&& request,
        const std::string& authenticated_id) const;
    virtual const std::string& LogKey(const DB::Log& r) const;
    virtual error::Error ValidateClientLog(const DB::Log& log) const;
    virtual size_t MaxRowSerializedSize() const;
   public_for_test:
    static std::pair<PrivateKey, PublicKey> NewKeys();
  };
  // P() returns a pointer to a _static_ Protocol object,
  // which will outlast the DB object.
  virtual const DB::Protocol* P() const;

  // Run a client log request and yield a response.
  // The client log should already have been checked with ValidateClientLog;
  // failing to do so will CHECK-fail.
  // It's assumed that validation happens on Raft log insert, so that
  // outputs from the Raft log are already validated.
  //
  // Output response is valid within the passed-in context.
  virtual DB::Response* Run(context::Context* ctx, const DB::Log& request);

  // Get rows from this database in range (exclusive_start, ...], returning
  // no more than [size] rows.  If it returns <[size] rows, the end of the database
  // has been reached.  Pass in empty string to start with the first key in
  // the database.  Returns the key of the largest returned row.
  virtual std::pair<std::string, error::Error> RowsAsProtos(
      context::Context* ctx,
      const std::string& exclusive_start,
      size_t size,
      google::protobuf::RepeatedPtrField<std::string>* out) const;
  // Update this database using the given database row states.
  // This will return an error if any of the DatabaseRowStates contain
  // rows that already exist within the database.  Rows must be lexigraphically
  // larger than any existing row in the database.  Returns the row key
  // of the last row inserted into the database, on success.
  virtual std::pair<std::string, error::Error> LoadRowsFromProtos(
      context::Context* ctx,
      const google::protobuf::RepeatedPtrField<std::string>& rows);

  // Compute a hash of the entire database.  This is not designed to
  // be useful for security-focussed integrity checking, but should be
  // sufficient to verify that replicated data matches up between source
  // and destination.
  virtual std::array<uint8_t, 32> Hash(context::Context* ctx) const;

  // Get the number of backups stored in the database
  virtual size_t row_count() const { return rows_.size(); }

 private:
  static std::pair<Element, error::Error> BlindEvaluate(context::Context* ctx, const PrivateKey& key, const Element& blinded_element);

  struct Row {
    PrivateKey priv;
    uint8_t tries;
  };
  std::map<BackupID, Row> rows_;

  void Create(
      context::Context* ctx,
      const BackupID& id,
      const std::string& privkey,
      const std::string& pubkey,
      const client::CreateRequest& req,
      client::CreateResponse* resp);
  void Evaluate(
      context::Context* ctx,
      const BackupID& id,
      const client::EvaluateRequest& req,
      client::EvaluateResponse* resp);
  void Remove(
      context::Context* ctx,
      const BackupID& id,
      const client::RemoveRequest& req,
      client::RemoveResponse* resp);
};

}  // namespace svr2::db

#endif  // __SVR2_DB_DB3_H__
