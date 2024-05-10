// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RAFT_INTERNAL_H__
#define __SVR2_RAFT_INTERNAL_H__

#include <optional>
#include <set>
#include <map>
#include "peerid/peerid.h"
#include "raft/types.h"
#include "raft/log.h"
#include "raft/membership.h"
#include "util/ticks.h"

namespace svr2::raft {

class Raft;  // forward declaration

namespace internal {

struct ReplicationState {
  // \* The next entry to send to each follower.
  // VARIABLE nextIndex
  LogIdx next_idx;

  // \* The latest entry that each follower has acknowledged is the same as the
  // \* leader's. This is used to calculate promiseIndex on the leader.
  // VARIABLE matchIndex
  LogIdx match_idx;
  // The latest entry that each follower has promised.  This is used
  // to calculate commitIndex on the leader.
  LogIdx promise_idx;

  // inflight - this field is very interesting, and is not part of the generic
  // Raft protocol.  As long as this is set to some LogIdx, we won't send
  // additional AppendRequests to this replica.  In generic Raft, this would
  // not work at all, as a single dropped message would break our ability to
  // ever append to its destination replica.  However, given that our host-side
  // message passing is in-order and lossless (the host will store-and-forward
  // our messages, never dropping them, until a message has been received and
  // acknowledged), this saves us sending duplicate logs over the network.
  // A crucial concern here, though, is that if for some reason a message is
  // dropped and we notice it, we must clear this value so that our next
  // AppendEntries will go through.
  std::optional<LogIdx> inflight;

  // send_probe requests that the next AppendEntries request to this peer
  // not contain any actual entries, just the log index we think they're
  // at.  This allows them to correct us without over-sending logs.
  bool send_probe;
  // send_heartbeat is set when nothing has changed, but the leader needs
  // to remind the followers that it does in fact still exist.
  bool send_heartbeat;
  // send_update is set when the leader needs to send a non-log update
  // to the followers (an update of promise or commit index).
  bool send_update;

  // the number of ticks since we last got a Raft message from this replica.
  util::Ticks last_seen_ticks;
};

enum class Role {
  FOLLOWER = 1,
  CANDIDATE = 2,
  LEADER = 3,
};

struct FollowerState {
  std::optional<peerid::PeerID> leader;
  util::Ticks election;
};
struct CandidateState {
  // \* The latest entry that each follower has acknowledged is the same as the
  // \* leader's. This is used to calculate commitIndex on the leader.
  // VARIABLE votesGranted
  std::set<peerid::PeerID> votes_granted;
  util::Ticks election;
};
struct LeaderState {
  std::map<peerid::PeerID, ReplicationState> followers;
  util::Ticks heartbeat;
  bool relinquishing;  // if true, this leader is trying to become a follower
};

}  // namespace internal
}  // namespace svr2::raft

#endif  // __SVR2_RAFT_INTERNAL_H__
