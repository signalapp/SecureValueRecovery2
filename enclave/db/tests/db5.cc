// Copyright 2025 Signal Messenger, LLC
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
//TESTDEP hmac
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "db/db5.h"
#include "env/env.h"
#include "util/log.h"
#include "util/endian.h"
#include "proto/client5.pb.h"
#include "proto/clientlog.pb.h"
#include "hmac/hmac.h"
#include <memory>

namespace svr2::db {

class DB5Test : public ::testing::Test {
 public:
  DB5Test() : db(&merk) {}
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  context::Context ctx;
  merkle::Tree merk;
  DB5 db;

  std::string Expected(const std::string& data, const std::string& password) {
    CHECK(data.size() == 32);
    CHECK(password.size() == 32);
    std::array<uint8_t, 32> k;
    std::copy(data.cbegin(), data.cend(), k.begin());
    auto h = hmac::HmacSha256(k, password);
    std::string out;
    out.resize(32);
    std::copy(h.cbegin(), h.cend(), out.begin());
    return out;
  }
};

TEST_F(DB5Test, SingleBackupLifecycle) {
  {
    client::Log5 log;
    auto u = log.mutable_req()->mutable_upload();
    log.set_backup_id("BACKUP7890123456");
    u->set_data("DATA5678901234567890123456789012");

    auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
    ASSERT_EQ(client::Response5::OK, resp->upload().status());
  }
  {
    client::Log5 log;
    auto d = log.mutable_req()->mutable_download();
    log.set_backup_id("BACKUP7890123456");
    d->set_password("PASSWORD901234567890123456789012");

    auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
    ASSERT_EQ(client::Response5::OK, resp->download().status());
    ASSERT_EQ(
        Expected("DATA5678901234567890123456789012", "PASSWORD901234567890123456789012"), 
        resp->download().output());
  }
  {
    client::Log5 log;
    auto d = log.mutable_req()->mutable_download();
    log.set_backup_id("BACKUP7890123456");
    d->set_password("password901234567890123456789012");

    auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
    ASSERT_EQ(client::Response5::OK, resp->download().status());
    ASSERT_EQ(
        Expected("DATA5678901234567890123456789012", "password901234567890123456789012"), 
        resp->download().output());
  }
  {  // purge
    client::Log5 log;
    auto r = log.mutable_req()->mutable_purge();
    log.set_backup_id("BACKUP7890123456");

    auto resp = dynamic_cast<client::Response*>(db.Run(&ctx, log));
  }
  {
    client::Log5 log;
    auto d = log.mutable_req()->mutable_download();
    log.set_backup_id("BACKUP7890123456");
    d->set_password("password901234567890123456789012");

    auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
    ASSERT_EQ(client::Response5::MISSING, resp->download().status());
  }
}

TEST_F(DB5Test, MultipleRows) {
  std::string backup_id("BACKUP789012345.");
  std::string data("DATA567890123456789012345678901.");
  for (int i = 0; i < 256; i++) {
    backup_id[DB5::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    {
      client::Log5 log;
      auto b = log.mutable_req()->mutable_upload();
      log.set_backup_id(backup_id);
      b->set_data(data);  // 32 bytes

      auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
      ASSERT_EQ(client::Response5::OK, resp->upload().status());
    }
  }
  for (int i = 0; i < 256; i++) {
    client::Log5 log;
    auto r = log.mutable_req()->mutable_download();
    backup_id[DB5::BACKUP_ID_SIZE-1] = i;
    data[31] = i;
    log.set_backup_id(backup_id);
    r->set_password("password901234567890123456789012");

    auto resp = dynamic_cast<client::Response5*>(db.Run(&ctx, log));
    ASSERT_EQ(client::Response5::OK, resp->download().status());
    ASSERT_EQ(
        Expected(data, "password901234567890123456789012"),
        resp->download().output());
  }
}

}  // namespace svr2::db
