// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP noise-c
//TESTDEP noisewrap
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <stdio.h>
#include <gtest/gtest.h>
#include "env/env.h"
#include "util/log.h"
#include <noise/protocol/randstate.h>
#include <noise/protocol/constants.h>
#include "util/hex.h"

namespace svr2 {

TEST(NoiseWrap, RandomnessIsWrappedDeterministically) {
  svr2::env::Init();
  std::array<uint8_t, 8> out;
  ASSERT_EQ(NOISE_ERROR_NONE, noise_randstate_generate_simple(out.data(), out.size()));
  LOG(INFO) << "RAND: " << util::ToHex(out);
  uint8_t expect[8] = {0x4f, 0x6f, 0xa8, 0x48, 0x32, 0xaa, 0x7d, 0x32};
  ASSERT_EQ(0, memcmp(out.data(), expect, 8));
}

}  // namespace svr2
