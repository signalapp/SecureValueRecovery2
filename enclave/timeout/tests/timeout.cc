// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP timeout
//TESTDEP metrics
//TESTDEP util
//TESTDEP context
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP sip
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "timeout/timeout.h"
#include "context/context.h"
#include "env/env.h"
#include "env/test/test.h"

namespace svr2::timeout {

class TimeoutTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  Timeout t;
  context::Context ctx;
};

TEST_F(TimeoutTest, TicksStartAtZero) {
  ASSERT_EQ(t.ticks(), 0);
}

TEST_F(TimeoutTest, TimeoutRuns) {
  bool ran = false;
  t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran = true; });
  ASSERT_FALSE(ran);
  t.TimerTick(&ctx);
  ASSERT_TRUE(ran);
}

TEST_F(TimeoutTest, TimeoutCancels) {
  bool ran = false;
  Cancel c = t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran = true; });
  ASSERT_FALSE(ran);
  t.CancelTimeout(&ctx, c);
  t.TimerTick(&ctx);
  ASSERT_FALSE(ran);
}

TEST_F(TimeoutTest, TimeoutCancelAfterRunIsFine) {
  bool ran = false;
  Cancel c = t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran = true; });
  ASSERT_FALSE(ran);
  t.TimerTick(&ctx);
  ASSERT_TRUE(ran);
  t.CancelTimeout(&ctx, c);
}

TEST_F(TimeoutTest, MultipleTimeoutsAtSameTick) {
  int ran = 0;
  t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran++; });
  Cancel c = t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran++; });
  t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran++; });
  t.SetTimeout(&ctx, 1, [&ran](context::Context* ctx){ ran++; });
  t.CancelTimeout(&ctx, c);
  t.TimerTick(&ctx);
  ASSERT_EQ(ran, 3);
}

TEST_F(TimeoutTest, FarFutureTimeout) {
  bool ran = false;
  t.SetTimeout(&ctx, 1001, [&ran](context::Context* ctx){ ran = true; });
  for (int i = 0; i < 1000; i++) {
    t.TimerTick(&ctx);
    ASSERT_FALSE(ran);
  }
  t.TimerTick(&ctx);
  ASSERT_TRUE(ran);
}

}  // namespace svr2::timeout
