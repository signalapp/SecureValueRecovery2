// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_TIMEOUT_TIMEOUT_H__
#define __SVR2_TIMEOUT_TIMEOUT_H__

#include <memory>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <functional>
#include "util/ticks.h"
#include "context/context.h"

namespace svr2::timeout {

class Timeout;
class Cancel {
 public:
  Cancel() : at_tick_(0), cancel_id_(0) {}
 private:
  Cancel(util::Ticks at_tick, int64_t cancel_id) : at_tick_(at_tick), cancel_id_(cancel_id) {}
  util::Ticks at_tick_;
  int64_t cancel_id_;
  friend class Timeout;
};

typedef std::function<void(context::Context*)> TimeoutFn;

class Timeout {
 public:
   Timeout();
  // SetTimeout provides a function that will be called [ticks_from_now] ticks in the future (min 1).
  // This function will be called at that time, once, unless CancelTimeout is called on the returned
  // value before that time.
  Cancel SetTimeout(context::Context* ctx, util::Ticks ticks_from_now, TimeoutFn fn) EXCLUDES(mu_);
  // CancelTimeout cancels a function that was scheduled for the future.  May be called any number
  // of times on a Cancel, and may be called after the ticks for the given function have
  // passed.
  void CancelTimeout(context::Context* ctx, const Cancel& c) EXCLUDES(mu_);
  // Called whenever the host gives us a TimerTick.
  void TimerTick(context::Context* ctx) EXCLUDES(mu_);

#ifdef IS_TEST
  util::Ticks ticks() const EXCLUDES(mu_) {
    util::unique_lock lock(mu_);
    return ticks_;
  }
#endif

 private:
  // Time and Timeouts
  mutable util::mutex mu_;
  util::Ticks ticks_ GUARDED_BY(mu_);
  int64_t timeout_cancel_gen_ GUARDED_BY(mu_);
  typedef std::unordered_map<int64_t, TimeoutFn> TimeoutSet;
  std::unordered_map<util::Ticks, TimeoutSet> timeouts_ GUARDED_BY(mu_);
};

}  // namespace svr2::timeout

#endif  // __SVR2_TIMEOUT_TIMEOUT_H__
