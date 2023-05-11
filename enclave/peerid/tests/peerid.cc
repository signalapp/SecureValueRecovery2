// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP sip
//TESTDEP sender
//TESTDEP env
//TESTDEP env/test
//TESTDEP util
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "peers/peers.h"
#include "env/env.h"
#include "util/log.h"
#include "proto/e2e.pb.h"
#include <memory>
#include <iostream>
#include <array>

namespace svr2::peerid {

class PeerIDTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(PeerIDTest, Valid) {
  PeerID id;
  ASSERT_FALSE(id.Valid());
  std::string more_valid = "12345678901234567890123456789012";
  ASSERT_EQ(error::OK, id.FromString(more_valid));
  ASSERT_TRUE(id.Valid());
}

TEST_F(PeerIDTest, FromString) {
  PeerID id;
  std::string valid = "12345678901234567890123456789012";
  ASSERT_EQ(error::OK, id.FromString(valid));
  std::array<uint8_t, 32> expected = {
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
      '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
  };
  ASSERT_EQ(expected, id.Get());
  ASSERT_NE(error::OK, id.FromString("badstring"));
  // We can set the string to invalid (all zeros), and FromString will still succeed.
  ASSERT_EQ(error::OK, id.FromString(std::string("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32)));
}

TEST_F(PeerIDTest, FromArray) {
  uint8_t in[32] = {1};
  PeerID id(in);
  std::array<uint8_t, 32> expected = {
      1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  };
  ASSERT_EQ(expected, id.Get());
}

TEST_F(PeerIDTest, Equality) {
  PeerID id1, id2;
  std::string valid = "12345678901234567890123456789012";
  std::string valid2 = "00045678901234567890123456789012";
  ASSERT_EQ(error::OK, id1.FromString(valid));
  ASSERT_EQ(error::OK, id2.FromString(valid));
  ASSERT_TRUE(id1 == id2);
  ASSERT_EQ(error::OK, id2.FromString(valid2));
  ASSERT_FALSE(id1 == id2);
  ASSERT_EQ(error::OK, id1.FromString(valid2));
  ASSERT_TRUE(id1 == id2);
}

TEST_F(PeerIDTest, DebugString) {
  PeerID id;
  ASSERT_EQ(id.DebugString(), "00000000");
  uint8_t in[32] = {1, 2, 3};
  id = PeerID(in);
  ASSERT_EQ(id.DebugString(), "01020300");
}

TEST_F(PeerIDTest, Copy) {
  PeerID id1;
  std::string valid = "12345678901234567890123456789012";
  ASSERT_EQ(error::OK, id1.FromString(valid));
  PeerID id2 = id1;
  ASSERT_TRUE(id1 == id2);
}

TEST_F(PeerIDTest, Mapping) {
  std::unordered_map<PeerID, uint8_t, PeerIDHasher> map;
  for (uint8_t i = 1; i <= 10; i++) {
    uint8_t in[32] = {i};
    map[PeerID(in)] = i;
  }
  for (uint8_t i = 1; i <= 10; i++) {
    uint8_t in[32] = {i};
    ASSERT_EQ(map[PeerID(in)], i);
  }
}

}  // namespace svr2::peerid
