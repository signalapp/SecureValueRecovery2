// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "timeout/timeout.h"
#include "metrics/metrics.h"

namespace svr2::timeout {

Timeout::Timeout() : ticks_(0), timeout_cancel_gen_(0) {}

void Timeout::TimerTick(context::Context* ctx) {
  ACQUIRE_NAMED_LOCK(lock, mu_, ctx, lock_timeout);
  ticks_++;
  auto timeouts_to_run = timeouts_.find(ticks_);
  if (timeouts_to_run == timeouts_.end()) {
    return;
  }
  TimeoutSet ts = std::move(timeouts_to_run->second);
  timeouts_.erase(timeouts_to_run);
  // We unlock before calling timeout methods, since they may want to do things
  // that also create timeouts.
  lock.unlock();
  for (auto iter = ts.begin(); iter != ts.end(); ++iter) {
    COUNTER(timeout, timeouts_run)->Increment();
    iter->second(ctx);
  }
}

Cancel Timeout::SetTimeout(context::Context* ctx, util::Ticks ticks_from_now, std::function<void(context::Context*)> fn) {
  ACQUIRE_LOCK(mu_, ctx, lock_timeout);
  CHECK(ticks_from_now + ticks_ > ticks_);
  Cancel tc(ticks_from_now + ticks_, ++timeout_cancel_gen_);
  auto finder = timeouts_.find(tc.at_tick_);
  if (finder == timeouts_.end()) {
    auto [i, b] = timeouts_.emplace(
        tc.at_tick_,
        std::unordered_map<int64_t, std::function<void(context::Context*)>>());
    finder = i;
  }

  finder->second[tc.cancel_id_] = fn;
  COUNTER(timeout, timeouts_created)->Increment();
  return tc;
}

void Timeout::CancelTimeout(context::Context* ctx, const Cancel& tc) {
  ACQUIRE_LOCK(mu_, ctx, lock_timeout);
  auto finder = timeouts_.find(tc.at_tick_);
  if (finder != timeouts_.end()) {
    auto f2 = finder->second.find(tc.cancel_id_);
    if (f2 != finder->second.end()) {
      COUNTER(timeout, timeouts_cancelled)->Increment();
      finder->second.erase(f2);
    }
  }
}

}  // namespace svr2::timeout
