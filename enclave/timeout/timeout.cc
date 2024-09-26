// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "timeout/timeout.h"
#include "metrics/metrics.h"

namespace svr2::timeout {

Timeout::Timeout() : ticks_(0), timeout_cancel_gen_(0) {}

void Timeout::TimerTick(context::Context* ctx) {
  ACQUIRE_NAMED_LOCK(lock, mu_, ctx, lock_timeout);
  MEASURE_CPU(ctx, cpu_timeout_timer_tick);
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
  // Try to do "the right thing" here if we get a 0 or negative [ticks_from_now],
  // by scheduling for as soon as possible.  We could try to run immediately,
  // but some calling contexts for this function may hold locks that the passed-in
  // function needs to also lock, so that could result in deadlocks.
  // Passing in such a value is technically a programmer error, but could be
  // the result of some bad math or the like, and we'd really rather not crash
  // the enclave.
  if (ticks_from_now + ticks_ <= ticks_) {
    ticks_from_now = 1;
  }
  // We just made this increment, so this should never CHECK-fail, unless we
  // are at ticks_==INT64_MAX, in which case we probably have bigger problems.
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
