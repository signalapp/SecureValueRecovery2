// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP util
//TESTDEP env
//TESTDEP libsodium
//TESTDEP protobuf-lite
#include <gtest/gtest.h>
#include "context/context.h"
#include "util/macros.h"
#include "util/mutex.h"
#include <time.h>
#include <pthread.h>
#include <mutex>

namespace svr2::util {

class AcquireLockTest : public ::testing::Test {
 public:
  util::mutex mu;
  int in_use GUARDED_BY(mu) = 0;

  static void* AcquireAndSleep(void* in) {
    auto t = (AcquireLockTest*) in;
    context::Context ctx;
    ACQUIRE_LOCK(t->mu, &ctx, lock_test);
    t->in_use++;
    for (int i = 0; i < 10; i++) {
      usleep(100000);
      CHECK(t->in_use == 1);
    }
    t->in_use--;
    CHECK(t->in_use == 0);
    return NULL;
  }

  static void* AcquireNamedAndSleep(void* in) {
    auto t = (AcquireLockTest*) in;
    context::Context ctx;
    ACQUIRE_NAMED_LOCK(lock, t->mu, &ctx, lock_test);
    t->in_use++;
    for (int i = 0; i < 10; i++) {
      usleep(100000);
      CHECK(t->in_use == 1);
    }
    t->in_use--;
    CHECK(t->in_use == 0);
    return NULL;
  }
};

TEST_F(AcquireLockTest, Unnamed) {
  pthread_t t1, t2, t3, t4;
  auto start = time(NULL);
  CHECK(0 == pthread_create(&t1, NULL, &AcquireLockTest::AcquireAndSleep, this));
  CHECK(0 == pthread_create(&t2, NULL, &AcquireLockTest::AcquireNamedAndSleep, this));
  CHECK(0 == pthread_create(&t3, NULL, &AcquireLockTest::AcquireAndSleep, this));
  CHECK(0 == pthread_create(&t4, NULL, &AcquireLockTest::AcquireNamedAndSleep, this));
  CHECK(0 == pthread_join(t1, NULL));
  CHECK(0 == pthread_join(t2, NULL));
  CHECK(0 == pthread_join(t3, NULL));
  CHECK(0 == pthread_join(t4, NULL));
  auto diff = time(NULL) - start;
  ASSERT_GE(diff, 3);
  ASSERT_LE(diff, 5);
}

}  // namespace svr2::util
