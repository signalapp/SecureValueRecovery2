// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "ristretto/ristretto.h"

namespace svr2::ristretto {

class RistrettoTest : public ::testing::Test {
};

TEST_F(RistrettoTest, ZeroIsValidAndCanonical) {
  Scalar s;
  ASSERT_TRUE(s.Valid());
  ASSERT_TRUE(s.IsZero());
}

}  // namespace svr2::ristretto
