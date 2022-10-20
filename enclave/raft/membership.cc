// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "raft/membership.h"
#include "util/log.h"
#include "metrics/metrics.h"
#include <iterator>

namespace svr2::raft {

std::pair<std::unique_ptr<Membership>, error::Error> Membership::FromProto(const ReplicaGroup& group) {
  std::unique_ptr<Membership> out(new Membership());

  for (const auto& replica : group.replicas()) {
    peerid::PeerID p;
    error::Error peer_err = p.FromString(replica.peer_id());
    if (peer_err != error::OK) {
      return std::make_pair(nullptr, peer_err);
    }
    if (out->all_replicas_.count(p)) {
      return std::make_pair(nullptr, COUNTED_ERROR(Membership_DuplicateReplicaInReplicaGroup));
    }
    out->all_replicas_.insert(p);
    if (replica.voting()) { out->voting_replicas_.insert(p); }
  }
  return std::make_pair(std::move(out), error::OK);
}

std::unique_ptr<Membership> Membership::First(const peerid::PeerID& me) {
  std::unique_ptr<Membership> out(new Membership());
  out->voting_replicas_.insert(me);
  out->all_replicas_.insert(me);
  return out;
}

// Returns the size of the set [a-b], IE: set a with all elements of set b removed from it.
size_t SetDiffSize(const std::set<peerid::PeerID>& a, const std::set<peerid::PeerID>& b) {
  auto a_iter = a.cbegin();
  auto b_iter = b.cbegin();
  size_t out = 0;
  while (a_iter != a.cend()) {
    if (b_iter == b.cend()) {
      ++out;
      ++a_iter;
    } else if (*a_iter < *b_iter) {
      ++a_iter;
      ++out;
    } else if (*b_iter < *a_iter) {
      ++b_iter;
    } else {  // *a_iter == *b_iter
      ++a_iter;
      ++b_iter;
    }
  }
  return out;
}

error::Error Membership::ValidProgressionForLeader(
    const peerid::PeerID& leader,
    const Membership& from,
    const Membership& to,
    size_t super_majority) {
  if (from.voting_replicas_.size() > super_majority && to.voting_replicas_.size() <= super_majority) {
    return COUNTED_ERROR(Membership_SuperMajorityLost);
  }
  size_t voting_additions = SetDiffSize(to.voting_replicas_, from.voting_replicas_);
  std::vector<peerid::PeerID> voting_removals;
  std::set_difference(
      from.voting_replicas_.begin(), from.voting_replicas_.end(),
      to.voting_replicas_.begin(), to.voting_replicas_.end(),
      std::back_inserter(voting_removals));
  size_t all_additions = SetDiffSize(to.all_replicas_, from.all_replicas_);
  std::vector<peerid::PeerID> all_removals;
  std::set_difference(
      from.all_replicas_.begin(), from.all_replicas_.end(),
      to.all_replicas_.begin(), to.all_replicas_.end(),
      std::back_inserter(all_removals));
  size_t all_changes = voting_additions + voting_removals.size() + all_additions + all_removals.size();
  if (to.voting_replicas_.size() == 0 || to.all_replicas_.size() == 0) {
    return COUNTED_ERROR(Membership_EmptySet);
  }
  if (all_changes == 2 && voting_removals.size() == 1 && all_removals.size() == 1 && voting_removals[0] == all_removals[0]) {
    // We allow there to be exactly two changes in the case where they are:
    // * remove peer X from voting replicas
    // * remove the same peer X from all replicas
    // We allow this so that, on shutdown, a replica can request to be fully
    // removed from the Raft group in a single step.
  } else if (all_changes > 1) {
    return COUNTED_ERROR(Membership_TooManyMembershipChanges);
  }
  if (all_changes == 0) {
    return COUNTED_ERROR(Membership_NoMembershipChanges);
  }
  if (!to.voting_replicas_.count(leader)) {
    return COUNTED_ERROR(Membership_LeaderRemovedFromVoting);
  }
  if (!to.all_replicas_.count(leader)) {
    return COUNTED_ERROR(Membership_LeaderRemovedFromAll);
  }
  if (SetDiffSize(to.all_replicas_, to.voting_replicas_) != to.all_replicas_.size() - to.voting_replicas_.size()) {
    return COUNTED_ERROR(Membership_VotingNotSubset);
  }
  return error::OK;
}

ReplicaGroup Membership::AsProto() const {
  ReplicaGroup g;
  for (auto peer : all_replicas_) {
    auto r = g.add_replicas();
    peer.ToString(r->mutable_peer_id());
    if (voting_replicas_.count(peer)) {
      r->set_voting(true);
    }
  }
  return g;
}

}  // namespace svr2::raft
