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
#include <pthread.h>
#include <time.h>

namespace svr2::socketwrap {

class SocketTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  static void* RunWriteThread(void* in) {
    size_t idx = reinterpret_cast<size_t>(in) & 1;
    SocketTest* stest = reinterpret_cast<SocketTest*>(reinterpret_cast<uintptr_t>(in) & (~static_cast<uintptr_t>(1)));
    stest->errs[idx] = stest->wqs[idx].WriteThread(stest->s[idx].get());
    return nullptr;
  }

  void SetUp() {
    errs[0] = error::OK;
    errs[1] = error::OK;
    CHECK(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
    s[0].reset(new Socket(socks[0]));
    s[1].reset(new Socket(socks[1]));
    CHECK(0 == pthread_create(&threads[0], NULL, &SocketTest::RunWriteThread, reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(this) + 0)));
    CHECK(0 == pthread_create(&threads[1], NULL, &SocketTest::RunWriteThread, reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(this) + 1)));
  }

  void StopAll() {
    wqs[0].KillThread();
    wqs[1].KillThread();
    pthread_join(threads[0], nullptr);
    pthread_join(threads[1], nullptr);
    CHECK(0 == close(socks[0]));
    CHECK(0 == close(socks[1]));
  }

  int socks[2];
  WriteQueue wqs[2];
  std::unique_ptr<Socket> s[2];
  pthread_t threads[2];
  error::Error errs[2];
};

TEST_F(SocketTest, SendAndReceive) {
  tests::SimplePB p1;
  p1.set_str("abcdefg");
  {
    context::Context ctx;
    ASSERT_EQ(error::OK, wqs[0].WritePB(&ctx, p1));
    tests::SimplePB p2;
    ASSERT_EQ(error::OK, s[1]->ReadPB(&ctx, &p2));
    ASSERT_EQ(p1.str(), p2.str());
  }

  for (int i = 0; i < 10; i++) {
    context::Context ctx;
    ASSERT_EQ(error::OK, wqs[1].WritePB(&ctx, p1));
  }
  for (int i = 0; i < 10; i++) {
    context::Context ctx;
    tests::SimplePB p2;
    ASSERT_EQ(error::OK, s[0]->ReadPB(&ctx, &p2));
    ASSERT_EQ(p1.str(), p2.str());
  }

  ASSERT_EQ(0, shutdown(socks[0], SHUT_WR));
  {
    context::Context ctx;
    EXPECT_EQ(error::OK, wqs[0].WritePB(&ctx, p1));
    sleep(1);  // Give the write thread a chance to notice the issue.
    EXPECT_EQ(error::Socket_Write, errs[0]);
  }
  {
    context::Context ctx;
    tests::SimplePB p2;
    EXPECT_EQ(error::Socket_ReadEOF, s[1]->ReadPB(&ctx, &p2));
  }
  StopAll();
}

TEST_F(SocketTest, ReadTooBig) {
  uint8_t too_big_buf[4] = {0xff, 0xff, 0xff, 0xff};
  s[0]->WriteAll(too_big_buf, sizeof(too_big_buf));

  tests::SimplePB pb;
  context::Context ctx;
  ASSERT_EQ(error::Socket_ReadTooBig, s[1]->ReadPB(&ctx, &pb));
  StopAll();
}

}  // namespace svr2::socketwrap
