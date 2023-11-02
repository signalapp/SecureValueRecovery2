// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP proto
//TESTDEP context
//TESTDEP metrics
//TESTDEP protobuf-lite
//TESTDEP libsodium
#include <gtest/gtest.h>
#include <deque>
#include "merkle/merkle.h"
#include "env/env.h"

namespace svr2::merkle {

class MerkleTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(MerkleTest, BasicUsage) {
  Tree t;
  {
    Leaf l1(&t);
    ASSERT_EQ(error::OK, l1.Verify(zero_hash));
    Hash h1 = {1, 2, 3};
    l1.Update(h1);
    ASSERT_EQ(error::OK, l1.Verify(h1));
    ASSERT_EQ(error::Merkle_VerifyLeaf, l1.Verify(zero_hash));
  }
  {
    Leaf l1(&t);
    ASSERT_EQ(error::OK, l1.Verify(zero_hash));
    Hash h1 = {1, 2, 3};
    l1.Update(h1);
    ASSERT_EQ(error::OK, l1.Verify(h1));
    ASSERT_EQ(error::Merkle_VerifyLeaf, l1.Verify(zero_hash));
  }
  EXPECT_EQ(0, COUNTER(merkle, leaves)->Value());
  EXPECT_EQ(1, COUNTER(merkle, nodes)->Value());
}

TEST_F(MerkleTest, AddThenRemoveAll) {
  {
    Tree t;
    std::deque<std::unique_ptr<Leaf>> leaves;
    for (int i = 0; i <= 10000; i++) {
      auto l = std::make_unique<Leaf>(&t);
      l->Update(Hash{1, ((uint8_t) i)});
      leaves.emplace_back(std::move(l));
      ASSERT_EQ(error::OK, leaves.front()->Verify(Hash{1, 0}));
    }
    for (int i = 0; i < 10000; i++) {
      leaves.pop_front();
      ASSERT_EQ(error::OK, leaves.back()->Verify(Hash{1, ((uint8_t) 10000)}));
    }
  }
  EXPECT_EQ(0, COUNTER(merkle, leaves)->Value());
  EXPECT_EQ(0, COUNTER(merkle, nodes)->Value());
}

}  // namespace svr2::queue
