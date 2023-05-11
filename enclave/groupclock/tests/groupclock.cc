// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP peerid
//TESTDEP sip
//TESTDEP sender
//TESTDEP context
//TESTDEP env
//TESTDEP env/test
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "groupclock/groupclock.h"
#include "env/env.h"
#include "context/context.h"

namespace svr2::groupclock {

class ClockTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
  context::Context ctx;
};

TEST_F(ClockTest, BasicUsage) {
  Clock c;
  EXPECT_EQ(0, c.GetTime(&ctx, std::set<peerid::PeerID>{}));
  c.SetLocalTime(1000);
  EXPECT_EQ(1000, c.GetTime(&ctx, std::set<peerid::PeerID>{}));
  peerid::PeerID p1((uint8_t[32]){1});
  peerid::PeerID p2((uint8_t[32]){2});
  peerid::PeerID p3((uint8_t[32]){3});
  peerid::PeerID p4((uint8_t[32]){4});
  c.SetRemoteTime(&ctx, p1, 1001);
  c.SetRemoteTime(&ctx, p2, 1002);
  c.SetRemoteTime(&ctx, p3, 1003);
  c.SetRemoteTime(&ctx, p4, 1004);
  EXPECT_EQ(1001, c.GetTime(&ctx, std::set<peerid::PeerID>{p1}));
  EXPECT_EQ(1001, c.GetTime(&ctx, std::set<peerid::PeerID>{p1, p2}));
  EXPECT_EQ(1002, c.GetTime(&ctx, std::set<peerid::PeerID>{p1, p2, p3}));
  EXPECT_EQ(1002, c.GetTime(&ctx, std::set<peerid::PeerID>{p1, p2, p3, p4}));
  c.SetLocalTime(1005);
  EXPECT_EQ(1003, c.GetTime(&ctx, std::set<peerid::PeerID>{p1, p2, p3, p4}));
  c.SetRemoteTime(&ctx, p1, 1004);
  EXPECT_EQ(1004, c.GetTime(&ctx, std::set<peerid::PeerID>{p1, p2, p3, p4}));
}

}  // namespace svr2::groupclock
