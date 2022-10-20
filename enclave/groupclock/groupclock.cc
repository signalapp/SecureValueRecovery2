// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "groupclock/groupclock.h"

#include <algorithm>
#include <vector>
#include "util/log.h"

namespace svr2::groupclock {

void Clock::SetLocalTime(util::UnixSecs secs) {
  local_.store(secs);
}

void Clock::SetRemoteTime(context::Context* ctx, const peerid::PeerID& peer, util::UnixSecs secs) {
  ACQUIRE_LOCK(mu_, ctx, lock_groupclock);
  remotes_[peer] = secs;
}

util::UnixSecs Clock::GetTime(context::Context* ctx, const std::set<peerid::PeerID>& remotes) const {
  std::vector<util::UnixSecs> secs(1 /* local_ */ + remotes.size());
  ACQUIRE_LOCK(mu_, ctx, lock_groupclock);
  auto set_iter = remotes.begin();
  auto map_iter = remotes_.begin();
  secs[0] = local_.load();
  size_t secs_size = 1;
  while (set_iter != remotes.end() && map_iter != remotes_.end()) {
    const peerid::PeerID& set_peer = *set_iter;
    const peerid::PeerID& map_peer = map_iter->first;
    if (set_peer < map_peer) {
      ++set_iter;
    } else if (map_peer < set_peer) {
      ++map_iter;
    } else {
      secs[secs_size++] = map_iter->second;
      ++set_iter;
      ++map_iter;
    }
  }
  secs.resize(secs_size);
  // `secs` now contains a list of my timestamp and the timestamps of all
  // peers in `remotes` that we've received a timestamp from.  Get the median.
  std::sort(secs.begin(), secs.end());
  return secs[secs.size()/2];
}

util::UnixSecs Clock::GetLocalTime() const {
  return local_.load();
}

}  // namespace svr2::groupclock
