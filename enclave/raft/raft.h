// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RAFT_RAFT_H__
#define __SVR2_RAFT_RAFT_H__

#include <memory>
#include <random>
#include <optional>
#include <list>
#include "peerid/peerid.h"
#include "proto/error.pb.h"
#include "proto/raft.pb.h"
#include "proto/msgs.pb.h"
#include "util/ticks.h"
#include "raft/types.h"
#include "raft/log.h"
#include "raft/internal.h"
#include "raft/membership.h"
#include "context/context.h"

namespace svr2::raft {

// MsgStr returns a debug string of the contents of [msg].
std::string MsgStr(const RaftMessage& msg);

// SendableRaftMessage wraps a message that should be sent out to one
// or a set of other Raft instances.  Messages are either broadcast,
// which should be sent to all `peers()` of the Raft instance, or
// targetted, which should be sent to a single instance.  If targetted,
// `to().has_value()` will be true.
class SendableRaftMessage {
 public:
  static SendableRaftMessage Broadcast(RaftMessage* msg) {
    return SendableRaftMessage(msg, std::optional<peerid::PeerID>());
  }
  static SendableRaftMessage Reply(const peerid::PeerID& to, RaftMessage* msg) {
    return SendableRaftMessage(msg, to);
  }
  const RaftMessage& message() { return *message_; }
  // If `!to().has_value()`, this is a broadcast message and should be
  // sent to all `raft.peers()`.
  const std::optional<peerid::PeerID>& to() { return to_; }
 private:
  SendableRaftMessage(RaftMessage* msg, std::optional<peerid::PeerID> t)
      : message_(msg), to_(t) {}
  RaftMessage* message_;
  // In the original rust Raft code, this was `from`, in a `Reply` enum.
  std::optional<peerid::PeerID> to_;
};

// Raft provides an implementation of the Raft protocol.
// This implementation is not safe for concurrent access.
//
// These are the major functions used to do Raft-y things:
//
//   Requesting and receiving actual log entries:
//     ClientRequest - request that an entry be added to the log
//     TakeCommittedLog - return the next log entry that's been committed
//   Internal Raft stuff:
//     Receive - receive a message from another Raft
//     SendableMessages - get any messages to send to other Raft
//     TimerTick - the inevitable march of time
//
// A creator of this class MUST:
//
// - regularly call TimerTick
// - call Receive whenever another Raft sends it a message
// - regularly call TakeCommittedLog and process the output
// - call SendableMessages after each call that takes a context::Context* and
//   consume the results before that context falls out of scope.
//
// A creator of this class MAY:
//
// - call ClientRequest to request that entries be appended to the canonical log
class Raft {
 public:
  DELETE_COPY_AND_ASSIGN(Raft);
  Raft(
      GroupId group,
      const peerid::PeerID& me,
      std::unique_ptr<Membership> membership,
      std::unique_ptr<Log> log,
      const enclaveconfig::RaftConfig& config,
      bool committed_log,
      size_t super_majority);

  // Simple getters

  // group_id contains a unique group identifier that allows the Raft instance
  // to make sure it's not accidentally talking to a different set of raft
  // servers than it thinks it is.  That way madness lies.
  const GroupId& group_id() const { return group_; }
  // last_applied returns the log index of the last log that has been requested,
  // but which may or may not be committed. 
  const LogIdx& last_applied() const { return last_applied_; }
  // commit_idx returns the log index of the last committed log.  This should
  // monotonically increase.
  const LogIdx& commit_idx() const { return commit_idx_; }
  // log returns a const reference to this Raft's underlying Log.  Note that Log
  // is not safe for concurrent access, so should not be accessed concurretly
  // with function calls on this Raft.
  const Log& log() const { return *log_; }
  // all_replicas returns the set of peer IDs for other members of this Raft's group.
  // It not contain the ID for this Raft.
  const std::set<peerid::PeerID>& all_replicas() const { return membership().all_replicas(); }
  const std::set<peerid::PeerID> peers() const {
    std::set out = membership().all_replicas();
    out.erase(me_);
    return out;
  }
  const Membership& committed_membership() const { return *membership_; }
  const peerid::PeerID& me() const { return me_; }
  // is_leader returns true when this Raft thinks it is the leader of the
  // Raft group.
  bool is_leader() const { return role_ == internal::Role::LEADER; }
  // leader returns the suspected current leader of this Raft group.
  std::optional<peerid::PeerID> leader() const;
  // current_term returns the current Raft term.
  const TermId& current_term() const { return current_term_; }
  // quorum_size returns the size of the smallest majority among this
  // Raft and its voting peers.
  static size_t quorum_size(size_t voting_replicas, size_t super_majority);
  size_t membership_quorum_size() const;
  // voting() returns true if we believe we are a voting member of the current
  // replica group.
  bool voting() const { return membership().voting_replicas().count(me_); }
  // If this is the leader, return the number of ticks ago when we saw a
  // message from the given follower.  If not leader or follower not found,
  // returns InvalidTicks.
  util::Ticks last_seen_ticks(const peerid::PeerID& follower) const;
  const enclaveconfig::RaftConfig& config() const { return config_; }
  error::Error FollowerReplicationStatus(const peerid::PeerID& follower, EnclavePeerReplicationStatus* status) const;

  // Simple setters
  void set_replication_chunk_size(size_t s) { config_.set_replication_chunk_bytes(s); }

  // More complicated functions.  For each function that takes a context::Context,
  // SendableMessages() must be called after that function completes and before
  // that context falls out of scope.

  // Request that a log entry containing the given data be added to the Raft log.
  // Requires that `is_leader()` is true.
  //
  // If successful, this log returns the location where the log _may_ be
  // committed. You can tell if the log was successfully added if TakeCommittedLog
  // returns a log entry with a matching location (term+idx).
  std::pair<LogLocation, error::Error> ClientRequest(context::Context* ctx, const std::string& data);
  // Request that a new replica group configuration be adopted by the Raft
  // group.  Requires that `is_leader()` is true, and that the configuration
  // is an acceptable next configuration from the current one.
  std::pair<LogLocation, error::Error> ReplicaGroupChange(context::Context* ctx, const ReplicaGroup& g);
  // Receive a Raft message from another replica.
  // Send messages from SendableMessages after this call.
  void Receive(context::Context* ctx, const RaftMessage& msg, const peerid::PeerID& from);
  // Tick the timer.  This code currently treats each call to this function
  // as a single tick.  Note that this does not currently correlate at all
  // with any real-time measure (it's not a second, per se).
  // Send messages from SendableMessages after this call.
  void TimerTick(context::Context* ctx);
  // ResetPeer lets this Raft instance know that the given peer ID
  // may have lost some of the messages we sent to it previously.
  void ResetPeer(context::Context* ctx, const peerid::PeerID& id);
  // Reconfigure sets the RaftConfig to a new value.
  void Reconfigure(const enclaveconfig::RaftConfig& config);
  // If I'm the leader, attempt to pawn that responsibility off on someone else.
  void RelinquishLeadership(context::Context* ctx);

  // Return the list of messages that should be sent to other peers.
  std::vector<SendableRaftMessage> SendableMessages() { return std::move(sendable_messages_); }

  // Pop the next committed log entry off the list, if there is one.
  // On success, LogIdx will be nonzero and LogEntry will be filled in
  // If there is no new committed log, LogIdx will be zero and LogEntry
  // will be empty.
  std::pair<LogIdx, LogEntry> TakeCommittedLog();

  const Membership& membership() const;

 #ifdef IS_TEST
  std::unique_ptr<Raft> Copy();
#endif // IS_TEST

 private:
  void set_heartbeat_timeout(util::Ticks t);
  void set_election_timeout(util::Ticks t);

  // MaybeBecomeLeader sometimes wants to append a log entry.  This call
  // allows it to do so without recursing MaybeChangeStateAndSendMessages.
  std::pair<LogLocation, error::Error> ClientRequestInternal(LogEntry* entry);
  // Set role and clear all current role state.
  void SetRole(internal::Role r);
  // Get the current leader as understood by this Raft, if there is one.
  std::optional<peerid::PeerID> Leader() const;
  // Append the given entry to the log.
  std::pair<LogLocation, error::Error> LogAppend(const LogEntry& entry);
  // Called by TimerTick() when an election timeout occurs to start a new election.
  void ElectionTimeout(context::Context* ctx);
  // Returns a new #ticks to wait before the next election, randomly (weak) in range
  // [election_timeout_, election_timeout_*2)
  util::Ticks RandomElectionTimeout() const;
  // Any RPC wiht a newer term causes the recipient to advance its term first.
  void UpdateTerm(const peerid::PeerID& peer, const RaftMessage& msg);
  // Returns true (and logs) if the given message should be dropped due to its term
  // being stale.
  bool ShouldDropResponseDueToStaleTerm(const peerid::PeerID& from, const RaftMessage& msg);
  // Check for any state changes that may require us to send more messages.
  void MaybeChangeStateAndSendMessages(context::Context* ctx);
  // Check if, as a candidate, we have enough to become the leader.
  // Part of MaybeChangeStateAndSendMessages.
  void MaybeBecomeLeader(context::Context* ctx);
  // Check if, given the information we have, we can advance the commit index.
  // Part of MaybeChangeStateAndSendMessages.
  void MaybeAdvanceCommitIndex();
  // Try to find a worthy replica to take over as leader.  If one is found,
  // send it a timeout_now to become the new leader.
  void TryToRelinquishLeadership(context::Context* ctx);
  // Set uncommitted membership on leader.
  void AddUncommittedMembership(LogIdx idx, std::unique_ptr<Membership> membership);
  void HandleMembershipChange();
  // See if uncommitted membership is now committed, and if so make it the
  // canonical one.
  void MaybeChangeUncommittedMembershipsBasedOnLog();
  // on uncommitted logs.
  // If leader, send message to peer_id requesting that they append entries to
  // their log.
  // Part of MaybeChangeStateAndSendMessages.
  void AppendEntries(context::Context* ctx, const peerid::PeerID& peer);
  // Get the next hash for the next log entry.
  std::array<uint8_t, 32> NextHash(const LogEntry& next_entry);

  // Request handlers
  void HandleVoteRequest(context::Context* ctx, const TermId& msg_term, const VoteRequest& msg, const peerid::PeerID& from);
  void HandleVoteResponse(context::Context* ctx, const TermId& msg_term, const VoteResponse& msg, const peerid::PeerID& from);
  void HandleAppendRequest(context::Context* ctx, const TermId& msg_term, const AppendRequest& msg, const peerid::PeerID& from);
  void HandleAppendResponse(context::Context* ctx, const TermId& msg_term, const AppendResponse& msg, const peerid::PeerID& from);

  void AddSendableMessage(SendableRaftMessage msg);
  error::Error ValidateReceivedMessage(context::Context* ctx, const RaftMessage& msg, const peerid::PeerID& from);
  enum CLH_Options {
    CLH_AllowNothing   = 0,
    CLH_AllowFuture    = 1 << 0,
  };
  error::Error CheckLogHash(const Log& log, LogIdx idx, TermId term, const std::string& hash, CLH_Options opts);

  // Message to request a vote for myself.  Requires role==candidate.
  RaftMessage* RequestVoteMessage(context::Context* ctx);

  GroupId group_;
  peerid::PeerID me_;
  std::unique_ptr<Membership> membership_;
  // uncommitted_memberships_ keeps an ordered list of the uncommitted-but-
  // active memberships based on the log.  We're effectively certain that
  // once a full request (AppendEntries, etc) is complete, this should have
  // exactly zero or one element in it, and thus can probably be not-a-list.
  std::list<std::pair<LogIdx, std::unique_ptr<Membership>>> uncommitted_memberships_;

  enclaveconfig::RaftConfig config_;

  LogIdx last_applied_;

  // \* The server's term number.
  // VARIABLE currentTerm
  TermId current_term_;

  // \* The candidate the server voted for in its current term, or
  // \* Nil if it hasn't voted for any.
  // VARIABLE votedFor
  std::optional<peerid::PeerID> voted_for_;

  // \* The server's state (Follower, Candidate, or Leader).
  // VARIABLE state
  internal::Role role_;
  internal::FollowerState follower_;
  internal::CandidateState candidate_;
  internal::LeaderState leader_;

  // \* A Sequence of log entries. The index into this sequence is the index of the
  // \* log entry. Unfortunately, the Sequence module defines Head(s) as the entry
  // \* with index 1, so be careful not to use that!
  // VARIABLE log
  std::unique_ptr<Log> log_;

  // \* The index of the latest entry in the log the state machine may apply.
  // VARIABLE commitIndex
  LogIdx commit_idx_;
  // We promise to commit at the given index; we will not truncate our log past
  // this point.
  LogIdx promise_idx_;

  // The list of messages that are generated to send out based on various actions.
  std::vector<SendableRaftMessage> sendable_messages_;

  size_t super_majority_;
};

}  // namespace svr2::raft

#endif  // __SVR2_RAFT_RAFT_H__
