// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP env
//TESTDEP env/test
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <vector>
#include <string>
#include <gtest/gtest.h>
#include "proto/msgs.pb.h"
#include "proto/error.pb.h"
#include "env/env.h"
#include "env/test/test.h"
#include "sender/sender.h"

namespace svr2::sender {

TEST(SenderTest, SendViaTestEnv) {
  env::Init();
  EnclaveMessage m;
  m.mutable_peer_message()->set_syn("abc");
  Send(m);
  Send(m);
  Send(m);
  std::vector<EnclaveMessage> got = env::test::SentMessages();
  ASSERT_EQ(3, got.size());
  ASSERT_EQ("abc", got[0].peer_message().syn());
  ASSERT_EQ("abc", got[1].peer_message().syn());
  ASSERT_EQ("abc", got[2].peer_message().syn());
}

}  // namespace svr2::sender
