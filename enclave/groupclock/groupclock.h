// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_GROUPCLOCK_GROUPCLOCK_H__
#define __SVR2_GROUPCLOCK_GROUPCLOCK_H__

#include <stdint.h>
#include <atomic>
#include <mutex>
#include "util/macros.h"
#include "util/mutex.h"
#include "util/ticks.h"
#include "peerid/peerid.h"
#include "context/context.h"

namespace svr2::groupclock {

// Clock that returns time based on times reported from a group of
// peers.  The reported time will be the median of all reported times.
class Clock {
 public:
  DELETE_COPY_AND_ASSIGN(Clock);
  Clock() : local_(0) {};
  void SetLocalTime(util::UnixSecs secs);
  void SetRemoteTime(context::Context* ctx, const peerid::PeerID& peer, util::UnixSecs secs) EXCLUDES(mu_);
  util::UnixSecs GetTime(context::Context* ctx, const std::set<peerid::PeerID>& remotes) const EXCLUDES(mu_);
  util::UnixSecs GetLocalTime() const;

 private:
  mutable util::mutex mu_;
  std::atomic<util::UnixSecs> local_;
  std::map<peerid::PeerID, util::UnixSecs> remotes_ GUARDED_BY(mu_);
};

}  // namespace svr2::groupclock

#endif
