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
//TESTDEP sip
#include <gtest/gtest.h>
#include <deque>
#include "merkle/merkle.h"
#include "env/env.h"
#include "util/hex.h"
#include "util/log.h"

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
    LOG(INFO) << "hash: " << util::ToHex(l1.hash());
    LOG(INFO) << "zhash: " << util::ToHex(zero_hash);
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
      if (i % 1000000 == 0) LOG(INFO) << i;
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

TEST_F(MerkleTest, BasicMove) {
  Tree t;
  Leaf l1(&t);
  Hash h1 = {1, 2, 3};
  l1.Update(h1);
  ASSERT_EQ(error::OK, l1.Verify(h1));
  Leaf l2 = std::move(l1);
  ASSERT_EQ(error::OK, l2.Verify(h1));
}

TEST_F(MerkleTest, CreateWithoutUpdateFailsToVerify) {
  Tree t;
  EXPECT_EQ(1, COUNTER(merkle, nodes)->Value());
  std::deque<Leaf> leaves;
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    leaves.emplace_back(&t);
    leaves.back().Update(Hash{1});
  }
  EXPECT_EQ(1, COUNTER(merkle, nodes)->Value());
  ASSERT_EQ(error::OK, leaves.front().Verify(Hash{1}));
  leaves.emplace_back(&t);
  EXPECT_EQ(3, COUNTER(merkle, nodes)->Value());
  // WE DO NOT VERIFY CORRECTLY HERE, since the new leaf did not call Update.
  ASSERT_NE(error::OK, leaves.front().Verify(Hash{1}));
  // Now, we fix that.
  leaves.back().Update(Hash{2});
  ASSERT_EQ(error::OK, leaves.front().Verify(Hash{1}));
}

}  // namespace svr2::queue
