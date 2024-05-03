// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP minimums
//TESTDEP env
//TESTDEP env/test
//TESTDEP util
//TESTDEP gtest
//TESTDEP proto
//TESTDEP context
//TESTDEP metrics
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include <unordered_map>
#include <string>
#include "minimums/minimums.h"
#include "env/env.h"
#include "context/context.h"

namespace svr2::minimums {

class MinimumsTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    env::Init(env::SIMULATED);
  }
  context::Context ctx;
};

TEST_F(MinimumsTest, SetLimits) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, UpdateLimitsWithSame) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, AddNewLimit) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["bing"] = "pot";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, KeyMissing) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  lim.mutable_lim()->erase("baz");
  ASSERT_EQ(error::Minimums_KeyMissing, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, EmptyKey) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())[""] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::Minimums_KeyEmpty, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, EmptyValue) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "";
  ASSERT_EQ(error::Minimums_EntryEmpty, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, KeyUpdate) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["baz"] = "zzzz";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, KeyUpdateLess) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["baz"] = "aaaa";
  ASSERT_EQ(error::Minimums_LimitDecreased, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, KeyUpdateSizeDiff) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  (*lim.mutable_lim())["baz"] = "blah";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["baz"] = "blah2";
  ASSERT_EQ(error::Minimums_SizeMismatch, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, KeyUpdateLowValue3) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = "bar";
  MinimumValues val;
  (*val.mutable_val())["foo"] = "aaa";
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  ASSERT_EQ(error::Minimums_ValueTooLow, m.CheckValues(&ctx, val));
}

TEST_F(MinimumsTest, U64s) {
  Minimums m;
  MinimumLimits lim;
  (*lim.mutable_lim())["foo"] = Minimums::U64(123);;
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["foo"] = Minimums::U64(124);;
  ASSERT_EQ(error::OK, m.UpdateLimits(&ctx, lim));
  (*lim.mutable_lim())["foo"] = Minimums::U64(123);;
  ASSERT_EQ(error::Minimums_LimitDecreased, m.UpdateLimits(&ctx, lim));
}

TEST_F(MinimumsTest, Combine) {
  MinimumValues into;
  (*into.mutable_val())["a"] = "aa";
  (*into.mutable_val())["b"] = "ba";
  (*into.mutable_val())["c"] = "ca";
  MinimumValues from;
  (*from.mutable_val())["a"] = "bb";
  (*from.mutable_val())["b"] = "ab";
  (*from.mutable_val())["d"] = "db";
  Minimums::CombineValues(from, &into);
  EXPECT_EQ(into.val().at("a"), "aa");
  EXPECT_EQ(into.val().at("b"), "ab");
  EXPECT_EQ(into.val().at("c"), "ca");
  EXPECT_EQ(into.val().at("d"), "db");
}

}  // namespace svr2::minimums
