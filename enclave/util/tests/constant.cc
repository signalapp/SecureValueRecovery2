// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP util
#include <gtest/gtest.h>
#include "util/constant.h"
#include <string>
#include <array>

namespace svr2::util {

class ConstantTest : public ::testing::Test {};

TEST_F(ConstantTest, Equality) {
  std::string a("abc");
  std::array<uint8_t, 3> b{'a', 'b', 'c'};
  EXPECT_TRUE(ConstantTimeEquals(a, a));
  EXPECT_TRUE(ConstantTimeEquals(a, b));
  EXPECT_TRUE(ConstantTimeEquals(b, a));
  std::string c("aBc");
  EXPECT_FALSE(ConstantTimeEquals(a, c));
  EXPECT_FALSE(ConstantTimeEquals(c, a));
  EXPECT_FALSE(ConstantTimeEquals(b, c));
  EXPECT_FALSE(ConstantTimeEquals(c, b));
}

}  // namespace svr2::util
