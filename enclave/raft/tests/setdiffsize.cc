// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP peerid
//TESTDEP context
//TESTDEP sip
//TESTDEP sender
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include <set>
#include "peerid/peerid.h"
#include "raft/membership.h"

namespace svr2::raft {

class SetDiffTest : public ::testing::Test {};

TEST_F(SetDiffTest, Basic) {
  std::set<peerid::PeerID> a;
  std::set<peerid::PeerID> b;
  ASSERT_EQ(0, SetDiffSize(a, b));
  uint8_t p1[32] = {1};
  uint8_t p2[32] = {2};
  uint8_t p3[32] = {3};
  uint8_t p4[32] = {4};
  a.insert(peerid::PeerID(p1));
  ASSERT_EQ(1, SetDiffSize(a, b));
  ASSERT_EQ(0, SetDiffSize(b, a));
  b.insert(peerid::PeerID(p2));
  b.insert(peerid::PeerID(p3));
  b.insert(peerid::PeerID(p4));
  ASSERT_EQ(1, SetDiffSize(a, b));
  ASSERT_EQ(3, SetDiffSize(b, a));
  a.insert(peerid::PeerID(p4));
  ASSERT_EQ(1, SetDiffSize(a, b));
  ASSERT_EQ(2, SetDiffSize(b, a));
}

}  // namespace svr2::raft
