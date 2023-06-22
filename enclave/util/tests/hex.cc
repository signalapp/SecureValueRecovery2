// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
#include <gtest/gtest.h>
#include "util/hex.h"
#include <string>

namespace svr2::util {

class HexTest : public ::testing::Test {};

TEST_F(HexTest, ToHex) {
  std::string a("\x01\x02\x0a");
  std::array<uint8_t, 3> b{4, 0x3b, 0xff};
  EXPECT_EQ("01020a", ToHex(a));
  EXPECT_EQ("043bff", ToHex(b));
}

TEST_F(HexTest, PrefixToHex) {
  std::array<uint8_t, 3> b{4, 0x3b, 0xff};
  EXPECT_EQ("", PrefixToHex(b, 0));
  EXPECT_EQ("043b", PrefixToHex(b, 2));
  EXPECT_EQ("043bff", PrefixToHex(b, 3));
  EXPECT_EQ("043bff", PrefixToHex(b, 4));
}

}  // namespace svr2::util
