// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP merkle
//TESTDEP sip
//TESTDEP context
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "db/db2.h"
#include "env/env.h"
#include "util/log.h"
#include "util/endian.h"
#include "proto/client.pb.h"
#include "proto/clientlog.pb.h"
#include <memory>

namespace svr2::db {

class DB2Test : public ::testing::Test {
 public:
  DB2Test() : db(&merk) {}
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  context::Context ctx;
  merkle::Tree merk;
  DB2 db;
};

TEST_F(DB2Test, SingleBackupLifecycle) {
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA56789012345678901234567890123456789012345678");
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
  {
    client::Log2 log;
    log.mutable_req()->mutable_tries();
    log.set_backup_id("BACKUP7890123456");
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::TriesResponse::OK, resp->tries().status());
    ASSERT_EQ(2, resp->tries().tries());
    ASSERT_EQ(false, resp->tries().exposed());
  }
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_expose();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA56789012345678901234567890123456789012345678");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::ExposeResponse::OK, resp->expose().status());
  }
  {
    client::Log2 log;
    log.mutable_req()->mutable_tries();
    log.set_backup_id("BACKUP7890123456");
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::TriesResponse::OK, resp->tries().status());
    ASSERT_EQ(2, resp->tries().tries());
    ASSERT_EQ(true, resp->tries().exposed());
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN45678901234567890123456789012");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::OK, resp->restore().status());
    ASSERT_EQ("DATA56789012345678901234567890123456789012345678", resp->restore().data());
    ASSERT_EQ(2, resp->restore().tries());
  }
  {
    client::Log2 log;
    log.mutable_req()->mutable_tries();
    log.set_backup_id("BACKUP7890123456");
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::TriesResponse::OK, resp->tries().status());
    ASSERT_EQ(2, resp->tries().tries());
    ASSERT_EQ(true, resp->tries().exposed());
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN............................2");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::PIN_MISMATCH, resp->restore().status());
    ASSERT_EQ("", resp->restore().data());
    ASSERT_EQ(1, resp->restore().tries());
  }
  {
    client::Log2 log;
    log.mutable_req()->mutable_tries();
    log.set_backup_id("BACKUP7890123456");
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::TriesResponse::OK, resp->tries().status());
    ASSERT_EQ(1, resp->tries().tries());
    ASSERT_EQ(true, resp->tries().exposed());
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN............................2");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::MISSING, resp->restore().status());
  }
}

TEST_F(DB2Test, SmallerData) {
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA5678901234567890123456789012");  // 32 bytes
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_expose();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA5678901234567890123456789012");  // 32 bytes

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::ExposeResponse::OK, resp->expose().status());
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN45678901234567890123456789012");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::OK, resp->restore().status());
    ASSERT_EQ("DATA5678901234567890123456789012", resp->restore().data());
  }
}

TEST_F(DB2Test, Delete) {
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA5678901234567890123456789012");  // 32 bytes
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_expose();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA5678901234567890123456789012");  // 32 bytes

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::ExposeResponse::OK, resp->expose().status());
  }
  {
    client::Log2 log;
    auto d = log.mutable_req()->mutable_delete_();
    log.set_backup_id("BACKUP7890123456");
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN45678901234567890123456789012");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::MISSING, resp->restore().status());
  }
}

TEST_F(DB2Test, MultipleRows) {
  std::string backup_id("BACKUP789012345.");
  std::string data("DATA567890123456789012345678901.");
  for (int i = 0; i < 256; i++) {
    backup_id[DB2::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    {
      client::Log2 log;
      auto b = log.mutable_req()->mutable_backup();
      log.set_backup_id(backup_id);
      b->set_data(data);  // 32 bytes
      b->set_pin("PIN45678901234567890123456789012");
      b->set_max_tries(2);

      auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
      ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
    }
    {
      client::Log2 log;
      auto b = log.mutable_req()->mutable_expose();
      log.set_backup_id(backup_id);
      b->set_data(data);  // 32 bytes

      auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
      ASSERT_EQ(client::ExposeResponse::OK, resp->expose().status());
    }
  }
  for (int i = 0; i < 256; i++) {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    backup_id[DB2::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    log.set_backup_id(backup_id);
    r->set_pin("PIN45678901234567890123456789012");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::OK, resp->restore().status());
    ASSERT_EQ(data, resp->restore().data());
  }
}

TEST_F(DB2Test, HashMatch) {
  std::string backup_id("BACKUP789012345.");
  std::string data("DATA567890123456789012345678901.");
  uint64_t hash = 0;
  for (int i = 0; i < 256; i++) {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    backup_id[DB2::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    log.set_backup_id(backup_id);
    b->set_data(data);  // 32 bytes
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
    uint64_t new_hash = util::BigEndian64FromBytes(db.Hash(&ctx).data());
    ASSERT_NE(hash, new_hash);  // hash changes with every database change.
    hash = new_hash;
  }
  ASSERT_EQ(hash, 12543638464623320991ULL);
}

TEST_F(DB2Test, HashMatchBackwards) {
  // Make sure that even if we construct the same DB in a different way
  // (in this case, by inserting back IDs in reverse of HashMatch), we
  // get the same result.
  std::string backup_id("BACKUP789012345.");
  std::string data("DATA567890123456789012345678901.");
  for (int i = 255; i >= 0; i--) {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    backup_id[DB2::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    log.set_backup_id(backup_id);
    b->set_data(data);  // 32 bytes
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
  ASSERT_EQ(util::BigEndian64FromBytes(db.Hash(&ctx).data()), 12543638464623320991ULL);
}

TEST_F(DB2Test, LoadRowsThenRecover) {
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_backup();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA56789012345678901234567890123456789012345678");
    b->set_pin("PIN45678901234567890123456789012");
    b->set_max_tries(2);

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
  {
    client::Log2 log;
    auto b = log.mutable_req()->mutable_expose();
    log.set_backup_id("BACKUP7890123456");
    b->set_data("DATA56789012345678901234567890123456789012345678");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::ExposeResponse::OK, resp->expose().status());
  }
  merkle::Tree m2;
  DB2 db2(&m2);
  // Replicate db->db2.
  {
    google::protobuf::RepeatedPtrField<std::string> rows;
    auto [s, err] = db.RowsAsProtos(&ctx, "", 2, &rows);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(1, rows.size());
    ASSERT_EQ("BACKUP7890123456", s);

    auto [s2, err2] = db2.LoadRowsFromProtos(&ctx, rows);
    ASSERT_EQ(error::OK, err2);
    ASSERT_EQ("BACKUP7890123456", s2);
  }
  {
    client::Log2 log;
    auto r = log.mutable_req()->mutable_restore();
    log.set_backup_id("BACKUP7890123456");
    r->set_pin("PIN45678901234567890123456789012");

    auto resp = dynamic_cast<client::Response*>(db2.Run(&ctx, log));
    ASSERT_EQ(client::RestoreResponse::OK, resp->restore().status());
    ASSERT_EQ("DATA56789012345678901234567890123456789012345678", resp->restore().data());
    ASSERT_EQ(2, resp->restore().tries());
  }
}

TEST_F(DB2Test, LoadManyRows) {
  client::Log2 log;
  log.set_backup_id("0000000000000000");
  auto b = log.mutable_req()->mutable_backup();
  b->set_data("DATA56789012345678901234567890123456789012345678");
  b->set_pin("PIN45678901234567890123456789012");
  b->set_max_tries(2);
  for (size_t i = 0; i <= 10000; i++) {
    if (i % 1000000 == 0) LOG(INFO) << i;
    util::BigEndian64Bytes(i, reinterpret_cast<uint8_t*>(log.mutable_backup_id()->data()));
    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
    ASSERT_EQ(client::BackupResponse::OK, resp->backup().status());
  }
}

}  // namespace svr2::db
