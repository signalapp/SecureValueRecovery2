// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP hmac
//TESTDEP noise-c
//TESTDEP libsodium

#include <array>
#include <string>

#include <gtest/gtest.h>

#include "hmac/hmac.h"

namespace svr2::hmac {

class HmacTest : public ::testing::Test {
};

TEST_F(HmacTest, BasicUsage) {
  std::array<uint8_t, 32> key = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2'};
  std::array<uint8_t, 32> out = HmacSha256(key, "abc");

  // Python3:
  //   >>> import base64
  //   >>> import hmac
  //   >>> import hashlib
  //   >>> base64.b16encode(hmac.digest(b'12345678901234567890123456789012', b'abc', hashlib.sha256))
  //   b'26B7F4C64769835D3F654DC635D5362988C270883270E1EFD65372B5F3100BAF'
  std::array<uint8_t, 32> expected = {
    0x26, 0xB7, 0xF4, 0xC6, 0x47, 0x69, 0x83, 0x5D,
    0x3F, 0x65, 0x4D, 0xC6, 0x35, 0xD5, 0x36, 0x29,
    0x88, 0xC2, 0x70, 0x88, 0x32, 0x70, 0xE1, 0xEF,
    0xD6, 0x53, 0x72, 0xB5, 0xF3, 0x10, 0x0B, 0xAF,
  };
  EXPECT_EQ(out, expected);
}

}  // namespace svr2::hmac
