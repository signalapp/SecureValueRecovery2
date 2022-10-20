// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "env/env.h"
#include "util/log.h"
#include "util/hex.h"

namespace svr2::env {

TEST(EnvTest, Random) {
  Init();
  uint8_t got[260];
  ASSERT_EQ(error::OK, environment->RandomBytes(got, sizeof(got)));
  LOG(INFO) << "Bytes: " << util::BytesToHex(got, 8);
  uint8_t expect_first[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  ASSERT_EQ(0, memcmp(got, expect_first, sizeof(expect_first)));
}

}  // namespace svr2::env
