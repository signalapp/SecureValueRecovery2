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
#include "raft/log.h"
#include "env/env.h"

namespace svr2::raft {

class LogTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(LogTest, BasicUsage) {
  Log log(1<<20);
  EXPECT_EQ(0, log.oldest_stored_idx());
  EXPECT_EQ(0, log.last_idx());
  EXPECT_EQ(1, log.next_idx());
  EXPECT_EQ(0, log.last_term());

  LogEntry e;
  e.set_term(1);
  e.set_hash_chain("12345678901234567890123456789012");
  ASSERT_EQ(error::OK, log.Append(e, 1));
  EXPECT_EQ(1, log.oldest_stored_idx());
  EXPECT_EQ(1, log.last_idx());
  EXPECT_EQ(2, log.next_idx());
  EXPECT_EQ(1, log.last_term());

  e.set_term(2);
  e.set_hash_chain("12345678901234567890123456789012");
  ASSERT_EQ(error::OK, log.Append(e, 1));
  EXPECT_EQ(1, log.oldest_stored_idx());
  EXPECT_EQ(2, log.last_idx());
  EXPECT_EQ(3, log.next_idx());
  EXPECT_EQ(2, log.last_term());

  auto i1 = log.At(4);
  EXPECT_FALSE(i1.Valid());
  auto i2 = log.At(0);
  EXPECT_FALSE(i2.Valid());
  auto i3 = log.At(1);
  EXPECT_TRUE(i3.Valid());
  EXPECT_EQ(1, i3.Index());
  EXPECT_EQ(1, i3.Term());
  EXPECT_EQ(36, i3.SerializedSize());
  i3.Next();
  EXPECT_TRUE(i3.Valid());
  EXPECT_EQ(2, i3.Index());
  EXPECT_EQ(2, i3.Term());
  EXPECT_EQ(36, i3.SerializedSize());
  i3.Next();
  EXPECT_FALSE(i3.Valid());
  EXPECT_EQ(0, i3.Index());
  EXPECT_EQ(0, i3.Term());
  EXPECT_EQ(0, i3.SerializedSize());

  EXPECT_EQ(1, log.oldest_stored_idx());
  EXPECT_EQ(2, log.last_idx());
  EXPECT_EQ(3, log.next_idx());
  EXPECT_EQ(2, log.last_term());
  auto i4 = log.At(2);
  EXPECT_TRUE(i4.Valid());
  EXPECT_EQ(2, i4.Index());
  EXPECT_EQ(2, i4.Term());
  EXPECT_EQ(36, i4.SerializedSize());
  i4.Next();
  EXPECT_FALSE(i4.Valid());
  EXPECT_EQ(0, i4.Index());
  EXPECT_EQ(0, i4.Term());
  EXPECT_EQ(0, i4.SerializedSize());
}

TEST_F(LogTest, RunningOutOfSpace) {
  LogEntry e;
  e.set_data("abc");
  e.set_hash_chain("12345678901234567890123456789012");
  e.set_term(1);
  size_t s = Log::logentry_bytes_in_log(e);
  ASSERT_EQ(s, 147);
  Log log(s*3+1);
  ASSERT_EQ(error::OK, log.Append(e, 1));
  ASSERT_EQ(error::OK, log.Append(e, 1));
  ASSERT_EQ(error::OK, log.Append(e, 1));
  ASSERT_EQ(error::Raft_LogOutOfSpace, log.Append(e, 1));
  ASSERT_EQ(3, log.last_idx());
  ASSERT_EQ(error::OK, log.Append(e, 2));
  ASSERT_EQ(error::Raft_LogOutOfSpace, log.Append(e, 2));
}

}  // namespace svr2::raft
