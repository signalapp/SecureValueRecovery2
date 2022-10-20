// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP util
#include <gtest/gtest.h>
#include "util/endian.h"
#include <string>
#include <string.h>

namespace svr2::util {

class EndianTest : public ::testing::Test {};

TEST_F(EndianTest, BigEndian64RoundTrip) {
  uint8_t buf[8] = {0};
  BigEndian64Bytes(0xfedcba9876543210ULL, buf);
  ASSERT_EQ(BigEndian64FromBytes(buf), 0xfedcba9876543210ULL);
  uint8_t expected[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  ASSERT_EQ(0, memcmp(buf, expected, 8));
}

TEST_F(EndianTest, BigEndian32RoundTrip) {
  uint8_t buf[4] = {0};
  BigEndian32Bytes(0xfedc4321UL, buf);
  ASSERT_EQ(BigEndian32FromBytes(buf), 0xfedc4321UL);
  uint8_t expected[8] = {0xfe, 0xdc, 0x43, 0x21};
  ASSERT_EQ(0, memcmp(buf, expected, 4));
}

}  // namespace svr2::util
