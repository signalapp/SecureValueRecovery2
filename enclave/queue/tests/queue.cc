// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include "queue/queue.h"
#include <time.h>

namespace svr2::queue {

class QueueTest : public ::testing::Test {};

void QueueReadThread(Queue<int>* q, int n) {
  int sum = 0;
  for (int i = 0; i < n; i++) {
    sum += q->Pop();
  }
  ASSERT_EQ(sum, n);
}

void QueueWriteThread(Queue<int>* q, int n) {
  for (int i = 0; i < n; i++) {
    q->Push(1);
  }
}

TEST_F(QueueTest, BasicUsage) {
  std::vector<std::thread> threads;
  Queue<int> q(16);
  for (int i = 0; i < 10; i++) {
    threads.emplace_back(QueueReadThread, &q, 1000);
  }
  sleep(1);
  for (int i = 0; i < 5; i++) {
    threads.emplace_back(QueueWriteThread, &q, 2000);
  }
  for (int i = 0; i < threads.size(); i++) {
    threads[i].join();
  }
}

}  // namespace svr2::queue
