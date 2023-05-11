// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP socketwrap
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium
#include <gtest/gtest.h>
#include "socketwrap/socket.h"
#include "proto/tests.pb.h"
#include "env/env.h"
#include "util/log.h"
#include "util/endian.h"
#include <sys/types.h>
#include <sys/socket.h>

namespace svr2::socketwrap {

class SocketTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
};

TEST_F(SocketTest, SendAndReceive) {
  int socks[2];
  ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, socks));

  Socket a(socks[0]);
  Socket b(socks[1]);

  tests::SimplePB p1;
  p1.set_str("abcdefg");
  {
    context::Context ctx;
    ASSERT_EQ(error::OK, a.WritePB(&ctx, p1));
    tests::SimplePB p2;
    ASSERT_EQ(error::OK, b.ReadPB(&ctx, &p2));
    ASSERT_EQ(p1.str(), p2.str());
  }

  for (int i = 0; i < 10; i++) {
    context::Context ctx;
    ASSERT_EQ(error::OK, b.WritePB(&ctx, p1));
  }
  for (int i = 0; i < 10; i++) {
    context::Context ctx;
    tests::SimplePB p2;
    ASSERT_EQ(error::OK, a.ReadPB(&ctx, &p2));
    ASSERT_EQ(p1.str(), p2.str());
  }

  ASSERT_EQ(0, shutdown(socks[0], SHUT_WR));
  {
    context::Context ctx;
    EXPECT_EQ(error::Socket_Write, a.WritePB(&ctx, p1));
  }
  {
    context::Context ctx;
    tests::SimplePB p2;
    EXPECT_EQ(error::Socket_ReadEOF, b.ReadPB(&ctx, &p2));
  }

  ASSERT_EQ(0, close(socks[0]));
  ASSERT_EQ(0, close(socks[1]));
}

TEST_F(SocketTest, ReadTooBig) {
  int socks[2];
  ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, socks));

  Socket a(socks[0]);
  Socket b(socks[1]);
  uint8_t too_big_buf[4] = {0xff, 0xff, 0xff, 0xff};
  a.WriteAll(too_big_buf, sizeof(too_big_buf));

  tests::SimplePB pb;
  context::Context ctx;
  ASSERT_EQ(error::Socket_ReadTooBig, b.ReadPB(&ctx, &pb));
  ASSERT_EQ(0, close(socks[0]));
  ASSERT_EQ(0, close(socks[1]));
}

}  // namespace svr2::socketwrap
