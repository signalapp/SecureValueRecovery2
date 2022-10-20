// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RAFT_MEMBERSHIP_H__
#define __SVR2_RAFT_MEMBERSHIP_H__

#include <memory>
#include "peerid/peerid.h"
#include "proto/error.pb.h"
#include "proto/raft.pb.h"

namespace svr2::raft {

size_t SetDiffSize(const std::set<peerid::PeerID>& a, const std::set<peerid::PeerID>& b);

class Membership {
 public:
  DELETE_ASSIGN(Membership);
  // First returns a membership from a proto, considering this to be
  // the first membership of Raft.
  static std::unique_ptr<Membership> First(const peerid::PeerID& me);
  // FromProto does minimal error checking and returns the membership as
  // ReplicaGroup describes it.
  static std::pair<std::unique_ptr<Membership>, error::Error> FromProto(const ReplicaGroup& group);

  const std::set<peerid::PeerID>& all_replicas() const { return all_replicas_; }
  const std::set<peerid::PeerID>& voting_replicas() const { return voting_replicas_; }

  // ValidProgressionForLeader checks if a change in membership from [from] to
  // [to] should be accepted by raft leader [leader].  If so, returns error::OK.
  // If not, returns an error explaining the issue.
  static error::Error ValidProgressionForLeader(
      const peerid::PeerID& leader,
      const Membership& from,
      const Membership& to,
      size_t super_majority);

  ReplicaGroup AsProto() const;

 public_for_test:
  Membership(const Membership& other) = default;  // allow copy
 private:
  Membership() = default;
  // all_replicas includes all peers, including me.
  std::set<peerid::PeerID> all_replicas_;
  // voting_replicas includes all replicas that can vote.
  std::set<peerid::PeerID> voting_replicas_;
};

}  // namespace svr2::raft

#endif  // __SVR2_RAFT_MEMBERSHIP_H__
