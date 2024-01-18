// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
#include <gtest/gtest.h>
#include "context/context.h"

namespace svr2::context {

class MeasureCPUTest : public ::testing::Test {
};

TEST_F(MeasureCPUTest, Unnamed) {
  // Make sure we don't cause any null-ptr exceptions, even
  // with repeated/interspersed IGNORE_CPU calls.
  context::Context ctx;
  MEASURE_CPU(&ctx, lock_test);
  IGNORE_CPU(&ctx);
  IGNORE_CPU(&ctx);
  MEASURE_CPU(&ctx, lock_test);
  MEASURE_CPU(&ctx, lock_test);
  MEASURE_CPU(&ctx, lock_test);
  IGNORE_CPU(&ctx);
  MEASURE_CPU(&ctx, lock_test);
  IGNORE_CPU(&ctx);
}

}  // namespace svr2::util
