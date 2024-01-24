// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP sip
//TESTDEP env
//TESTDEP env/test
//TESTDEP gtest
//TESTDEP context
//TESTDEP metrics
//TESTDEP util
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include <unordered_map>
#include <string>
#include "sip/hasher.h"
#include "env/env.h"

namespace svr2::sip {

class HashInts : public Half {
 public:
  size_t operator()(const uint32_t& a) const {
    return HashU64(&a, sizeof(a));
  }
};

class HasherTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(HasherTest, HashInts) {
  std::unordered_map<uint32_t, uint32_t, HashInts> m;
  for (uint32_t i = 0; i < 5000; i++) {
    m[i] = i;
  }
  for (uint32_t i = 0; i < 5000; i++) {
    ASSERT_EQ(m[i], i);
  }
}

}  // namespace svr2::sip
