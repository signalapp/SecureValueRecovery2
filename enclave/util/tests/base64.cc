// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP metrics
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP context
//TESTDEP libsodium

#include <array>
#include <string>

#include <gtest/gtest.h>

#include "util/base64.h"
#include "env/env.h"

namespace svr2::util {

class Base64Test : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(Base64Test, Decode) {
  std::string in("TWFu");
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("Man", in);
  in = "TWE";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("Ma", in);
  in = "TWE=";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("Ma", in);
  in = "TQ";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("M", in);
  in = "TQ=";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("M", in);
  in = "TQ==";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("M", in);
  in = "TQ=====";
  ASSERT_EQ(error::OK, B64DecodeInline(&in, B64STD));
  ASSERT_EQ("M", in);
  in = "TQ==x";
  ASSERT_EQ(error::Util_Base64InvalidPadding, B64DecodeInline(&in, B64STD));
}

}  // namespace svr2::util
