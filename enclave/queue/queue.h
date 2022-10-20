// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_QUEUE_QUEUE_H__
#define __SVR2_QUEUE_QUEUE_H__

#include <mutex>
#include <deque>
#include <condition_variable>
#include "util/macros.h"

namespace svr2::queue {

template <class T>
class Queue {
 public:
  Queue(size_t max_size) : max_size_(max_size) {}

  void Push(T val) {
    std::unique_lock lock(mu_);
    notfull_.wait(lock, [this]{ return d_.size() < max_size_; });
    d_.emplace_back(std::move(val));
    lock.unlock();
    full_.notify_one();
  }

  T Pop() {
    std::unique_lock lock(mu_);
    full_.wait(lock, [this]{ return d_.size() > 0; });
    T out = std::move(d_.front());
    d_.pop_front();
    lock.unlock();
    notfull_.notify_one();
    return out;
  }

 private:
  std::mutex mu_;
  std::condition_variable full_;
  std::condition_variable notfull_;
  std::deque<T> d_;
  size_t max_size_;
};

}  // namespace svr2::queue

#endif  // __SVR2_QUEUE_QUEUE_H__
