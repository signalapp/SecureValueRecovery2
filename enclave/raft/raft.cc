// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "raft/raft.h"
#include <cstdlib>
#include "util/log.h"
#include <sstream>
#include "metrics/metrics.h"
#include "hmac/hmac.h"
#include "util/constant.h"
#include "util/bytes.h"
#include "util/endian.h"
#include "util/hex.h"

#define MELOG(x) LOG(x) << "(" << me().DebugString() << ") "

namespace svr2::raft {

Raft::Raft(
    GroupId group,
    const peerid::PeerID& me,
    merkle::Tree* merk,
    std::unique_ptr<Membership> mem,
    std::unique_ptr<Log> log,
    const enclaveconfig::RaftConfig& config,
    bool committed_log,
    size_t super_majority)
    : group_(group),
      me_(me),
      merkle_(merk),
      membership_(std::move(mem)),
      config_(config),
      last_applied_(committed_log ? log->last_idx() : 0),
      current_term_(0),
      log_(std::move(log)),
      commit_leaf_(merk),
      commit_idx_(committed_log ? log_->last_idx() : 0),
      promise_leaf_(merk),
      promise_idx_(committed_log ? log_->last_idx() : 0),
      super_majority_(super_majority) {
  SetRole(internal::Role::FOLLOWER);
  follower_.election = RandomElectionTimeout();
  GAUGE(raft, commit_index)->Set(commit_idx_);
  GAUGE(raft, promise_index)->Set(promise_idx_);
  context::Context ctx;
  UpdateMerkleTree(&ctx);
  if (voting() && membership().voting_replicas().size() == 1) {
    // This is a one-instance replica and I'm voting, become leader.
    ElectionTimeout(&ctx);
    MaybeChangeStateAndSendMessages(&ctx);
    CHECK(sendable_messages_.size() == 0);
  }
}

size_t Raft::membership_quorum_size() const {
  return quorum_size(membership().voting_replicas().size(), super_majority_);
}

size_t Raft::quorum_size(size_t voting_replicas, size_t super_majority) {
  return std::min(
      voting_replicas,
      (voting_replicas - super_majority) / 2 + 1 + super_majority);
}

static const char* RoleName(internal::Role r) {
  switch (r) {
    case internal::Role::LEADER: return "LEADER";
    case internal::Role::CANDIDATE: return "CANDIDATE";
    case internal::Role::FOLLOWER: return "FOLLOWER";
  }
  return "UNKNOWN_ROLE";
}

void Raft::SetRole(internal::Role r) {
  MELOG(INFO) << "Raft switching to role " << RoleName(r) << " at term " << current_term_;
  role_ = r;
  leader_ = {};
  follower_ = {};
  candidate_ = {};
  GAUGE(raft, role)->Set(static_cast<uint64_t>(r));
}

std::pair<LogIdx, LogEntry> Raft::TakeCommittedLog() {
  if (last_applied_ >= commit_idx_) {
    return std::make_pair(0, LogEntry());
  }
  last_applied_++;
  // If it's committed, we should have it.
  auto iter = log_->At(last_applied_);
  CHECK(iter.Valid());
  LogEntry out(*iter.Entry());
  return std::make_pair(last_applied_, std::move(out));
}

std::optional<peerid::PeerID> Raft::leader() const {
  switch (role_) {
    case internal::Role::FOLLOWER: return follower_.leader;
    case internal::Role::CANDIDATE: return std::optional<peerid::PeerID>();
    case internal::Role::LEADER: return std::optional<peerid::PeerID>(me_);
    default: CHECK(nullptr == "Raft state without valid role");
  }
}
void Raft::set_election_timeout(util::Ticks t) {
  config_.set_election_ticks(t);
  follower_.election = std::min(t, follower_.election);
  candidate_.election = std::min(t, candidate_.election);
}
void Raft::set_heartbeat_timeout(util::Ticks t) {
  config_.set_heartbeat_ticks(t);
  leader_.heartbeat = t;
}
void Raft::TimerTick(context::Context* ctx) {
  switch (role_) {
    case internal::Role::FOLLOWER:
      if (0 >= --follower_.election) {
        LOG(INFO) << "follower election timeout";
        ElectionTimeout(ctx);
      }
      break;
    case internal::Role::CANDIDATE:
      if (0 >= --candidate_.election) {
        LOG(INFO) << "candidate election timeout";
        ElectionTimeout(ctx);
      }
      break;
    case internal::Role::LEADER:
      for (auto i = leader_.followers.begin(); i != leader_.followers.end(); ++i) {
        if (i->second.last_seen_ticks != util::InvalidTicks) {
          i->second.last_seen_ticks++;
        }
      }
      if (0 >= --leader_.heartbeat) {
        LOG(VERBOSE) << "leader sending heartbeat";
        for (auto i = leader_.followers.begin(); i != leader_.followers.end(); ++i) {
          i->second.send_heartbeat = true;
        }
        leader_.heartbeat = config_.heartbeat_ticks();
      }
      break;
  }
  MaybeChangeStateAndSendMessages(ctx);
}

void Raft::ResetPeer(context::Context* ctx, const peerid::PeerID& id) {
  if (!membership().all_replicas().count(id)) {
    // Don't bother doing anything if this isn't one of our Raft peers.
    return;
  }
  switch (role_) {
    case internal::Role::FOLLOWER:
      return;
    case internal::Role::CANDIDATE:
      // Since this peer may have lost messages, it may have lost our
      // request for a vote, so resend it.
      AddSendableMessage(SendableRaftMessage::Reply(id, RequestVoteMessage(ctx)));
      return;
    case internal::Role::LEADER: {
      auto finder = leader_.followers.find(id);
      if (finder == leader_.followers.end()) { return; }
      internal::ReplicationState& state = finder->second;
      state.next_idx = log_->last_idx() + 1;
      state.send_probe = true;
      state.send_heartbeat = true;
      state.inflight.reset();
      // We don't reset last_seen_ticks yet, because we haven't gotten
      // a RAFT message from them.  But the above means that we will
      // send them a message, so we should reset it soon when we get our reply.
    } return;
  }
}
void Raft::Reconfigure(const enclaveconfig::RaftConfig& config) {
  MELOG(INFO) << "reconfiguring raft";
  config_ = config;
  set_election_timeout(config_.election_ticks());
  set_heartbeat_timeout(config.heartbeat_ticks());
}

void Raft::RelinquishLeadership(context::Context* ctx) {
  if (role_ != internal::Role::LEADER || leader_.relinquishing) { return; }

  // Append a noop to the end of the log.  Since we then wait for the first
  // replica that reaches the end of our log, this makes sure that we find a replica
  // that is up and running at the time of this call.  Otherwise, it's possible that
  // we could have a quiescent Raft group and the replica we choose may no longer
  // be responding.
  ClientRequestInternal(ctx->Protobuf<LogEntry>());

  leader_.relinquishing = true;
  MaybeChangeStateAndSendMessages(ctx);
}

std::pair<LogLocation, error::Error> Raft::LogAppend(const LogEntry& entry) {
  error::Error err = error::OK;
  std::unique_ptr<Membership> new_uncommitted_membership;
  if (entry.has_membership_change()) {
    auto [mem, err] = Membership::FromProto(entry.membership_change());
    if (err != error::OK) {
      COUNTER(raft, logs_append_failure)->Increment();
      LOG(ERROR) << "failing to append invalid membership change in Raft uncommitted log at idx="
          << log_->next_idx() << ", " << err;
      return std::make_pair(LogLocation(), err);
    }
    new_uncommitted_membership = std::move(mem);
  }
  if (error::OK != (err = log_->Append(entry, last_applied_))) {
    // Some unhandleable Raft error occurred.
    COUNTER(raft, logs_append_failure)->Increment();
    return std::make_pair(LogLocation(), err);
  }
  LogLocation loc;
  loc.set_term(current_term_);
  loc.set_idx(log_->last_idx());
  loc.set_hash_chain(entry.hash_chain());
  if (new_uncommitted_membership.get() != nullptr) {
    AddUncommittedMembership(loc.idx(), std::move(new_uncommitted_membership));
  }
  COUNTER(raft, logs_append_success)->Increment();
  return std::make_pair(loc, error::OK);
}

//
// -- raft TLA+ parallel code --
// the code below is so similar to Raft's TLA+ code that the TLA+ is provided
// in the right-hand column for sections which correspond almost exactly. code
// is provided in the same order as the TLA+ so that the reader can follow.
//

//
// \* Define state transitions
//

// \* Server i times out and starts a new election.
void Raft::ElectionTimeout(context::Context* ctx) {
  if (!voting()) {
    LOG(WARNING) << "not a voting member, skipping election request";
    // If we're a non-voting follower, reset our election ticks.
    follower_.election = RandomElectionTimeout();
    return;
  }
  COUNTER(raft, election_timeouts)->Increment();
  switch (role_) {
    case internal::Role::CANDIDATE:
    case internal::Role::FOLLOWER: {
      // /\ state[i] \in {Follower, Candidate}
      // /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
      // \* Most implementations would probably just set the local vote
      // \* atomically, but messaging localhost for it is weaker.
      current_term_++;
      GAUGE(raft, current_term)->Set(current_term_);
      // /\ votedFor' = [votedFor EXCEPT ![i] = Nil]
      voted_for_ = me_;
      // /\ votesGranted'   = [votesGranted EXCEPT ![i] = {}]
      std::set<peerid::PeerID> votes_granted;
      votes_granted.insert(me_);

      // /\ state' = [state EXCEPT ![i] = Candidate]
      SetRole(internal::Role::CANDIDATE);
      candidate_ = {
        .votes_granted = std::move(votes_granted),
        .election = RandomElectionTimeout(),
      };

      MELOG(INFO) << "became candidate at term " << current_term_;
      AddSendableMessage(SendableRaftMessage::Broadcast(RequestVoteMessage(ctx)));
      break;
    }
    default:
      break;
  }
}

// \* Candidate i sends j a RequestVote request.
RaftMessage* Raft::RequestVoteMessage(context::Context* ctx) {
  // RequestVote(i,j) ==
  // /\ state[i] = Candidate
  CHECK(role_ == internal::Role::CANDIDATE);
  // /\ Send([
  auto msg = ctx->Protobuf<RaftMessage>();
  msg->set_group(group_);
  //          mterm         |-> currentTerm[i],
  msg->set_term(current_term_);
  //          mtype         |-> RequestVoteRequest,
  auto vote_req = msg->mutable_vote_request();
  //          mlastLogTerm  |-> LastTerm(log[i]),
  vote_req->set_last_log_term(log_->last_term());
  //          mlastLogIndex |-> Len(log[i]),
  vote_req->set_last_log_idx(log_->last_idx());
  //          mlastLogHash  |-> Hash(log[i])
  auto iter = log_->At(log_->last_idx());
  vote_req->set_last_log_hash_chain(iter.Valid() ? iter.Entry()->hash_chain() : "");
  return msg;
}

// \* Leader i sends j an AppendEntries request containing up to 1 entry.
// The TLA+ spec for Raft limits AppendEntries requests to just one log entry
// because it minimizes atomic regions without loss of generality.
// This implementation allows multiple log entries in a request.
void Raft::AppendEntries(context::Context* ctx, const peerid::PeerID& peer) {
  // AppendEntries(i, j) ==
  // /\ state[i] = Leader
  if (role_ != internal::Role::LEADER) { return; }
  // /\ i /= j
  if (0 == leader_.followers.count(peer)) { return; }
  internal::ReplicationState& replication = leader_.followers[peer];
  uint64_t last_log_idx = log_->last_idx();
  uint64_t next_idx = replication.next_idx;
  bool send_entries = last_log_idx >= next_idx && !replication.send_probe;
  if (!send_entries && !replication.send_heartbeat && !replication.send_probe) { return; }
  if (replication.inflight.has_value()) { return; }
  MELOG(VERBOSE) << "sending appendentries to " << peer;

  // /\ LET prevLogIndex == nextIndex[i][j] - 1
  LogIdx prev_log_idx = next_idx - 1;
  //        prevLogTerm == IF prevLogIndex > 0 THEN
  //                           log[i][prevLogIndex].term
  //                       ELSE
  //                           0
  uint64_t prev_log_term = prev_log_idx == 0 ? 0 : log_->At(prev_log_idx).Term();
  
  //         prevLogHash == IF prevLogIndex > 0 THEN
  //                            log[i][prevLogIndex].hashChain
  //                        ELSE
  //                            0
  // \* Note that log truncation is not modeled in the TLA+
  auto prev_log_hash_chain = (prev_log_idx == 0 || !log_->At(prev_log_idx).Valid())
                              ? std::string("") : log_->At(prev_log_idx).Entry()->hash_chain();
  if (prev_log_term == 0 && prev_log_idx != 0) {
    LOG(ERROR) << "missing log " << prev_log_idx << " to send to " << peer;
    return;
  }
  std::vector<LogEntry> entries;
  LogIdx last_entry = prev_log_idx;
  //        \* Send entries, constrained by the end of the log and config_.replication_chunk_bytes.
  if (send_entries) {
    size_t total_entries_size = 0;
    const size_t max_entries_size = config_.replication_chunk_bytes();
    const uint64_t start_entry = next_idx;
    const uint64_t limit_entry = last_log_idx + 1;
    //        entries == SubSeq(log[i], nextIndex[i][j], lastEntry)
    for (uint64_t entry_idx = start_entry; entry_idx < limit_entry; entry_idx++) {
      const LogEntry* e = log_->At(entry_idx).Entry();
      if (e == nullptr) {
        LOG(ERROR) << "error fetching raft log " << entry_idx << " to send to " << peer;
        break;
      }
      entries.emplace_back(*e);
      total_entries_size += e->ByteSizeLong();
      if (total_entries_size >= max_entries_size) {
        LOG(WARNING) << "not all log entries in [" << start_entry << ", " << limit_entry
                     << ") sent due to size constraint.  At " << entry_idx
                     << ", size " << total_entries_size << " >= " << max_entries_size;
        break;
      }
    }
    // \* The following TLA+ constrained the replica to send at most one entry. We send multiple.
    //       lastEntry == Min({Len(log[i]), nextIndex[i][j]})
    last_entry = prev_log_idx + entries.size();
  }
    
  //    IN Send([
  auto msg = ctx->Protobuf<RaftMessage>();
  msg->set_group(group_);
  //             mterm          |-> currentTerm[i],
  msg->set_term(current_term_);
  //             mtype          |-> AppendEntriesRequest,
  auto append = msg->mutable_append_request();
  //             mprevLogIndex  |-> prevLogIndex,
  append->set_prev_log_idx(prev_log_idx);
  //             mprevLogTerm   |-> prevLogTerm,
  append->set_prev_log_term(prev_log_term);
  //             \* Signal TLA+ extension
  //             mprevLogHash   |-> prevLogHash
  append->set_prev_log_hash_chain(prev_log_hash_chain);
  //             mentries       |-> entries,
  for (size_t i = 0; i < entries.size(); i++) {
    *append->add_entries() = std::move(entries[i]);
  }
  //             mcommitIndex   |-> Min({commitIndex[i], lastEntry}),
  append->set_leader_commit(std::min(commit_idx_, last_entry));
  //             \* Signal TLA+ extension
  //              mpromiseIndex  |-> Min({promiseIndex[i], lastEntry}),
  append->set_leader_promise(std::min(promise_idx_, last_entry));

  replication.send_heartbeat = false;
  replication.inflight = last_entry;
  AddSendableMessage(SendableRaftMessage::Reply(peer, msg));
}

void Raft::MaybeBecomeLeader(context::Context* ctx) {
  // BecomeLeader(i) ==
  // /\ state[i] = Candidate
  if (role_ != internal::Role::CANDIDATE) { return; }
  // /\ votesGranted[i] \in Quorum
  if (candidate_.votes_granted.size() < membership_quorum_size()) { return; }
  LOG(INFO) << "becoming leader at " << current_term_;
  SetRole(internal::Role::LEADER);
  leader_ = {
    .heartbeat = 0,
  };
  for (auto peer : membership().all_replicas()) {
    if (peer == me_) continue;
    leader_.followers[peer] = {
      // /\ nextIndex'  = [nextIndex EXCEPT ![i] = [j \in Server |-> Len(log[i]) + 1]]
      .next_idx = log_->next_idx(),
      // /\ matchIndex' = [matchIndex EXCEPT ![i] = [j \in Server |-> 0]]
    };
  }
  // append a noop in the new term to commit entries from past terms (Raft Section 5.4.2)
  ClientRequestInternal(ctx->Protobuf<LogEntry>());
}

void Raft::AddUncommittedMembership(
    LogIdx idx, std::unique_ptr<Membership> uncommitted_membership) {
  // Uncommitted memberships should always be stored in log index order.
  CHECK(uncommitted_memberships_.size() == 0
      || uncommitted_memberships_.back().first < idx);
  uncommitted_memberships_.emplace_back(idx, std::move(uncommitted_membership));
  HandleMembershipChange();
}

void Raft::HandleMembershipChange() {
  if (role_ == internal::Role::LEADER) {
    // If there's any new followers (voting or not) in the new uncommitted
    // membership, add them to the current leader's [followers] map.
    for (auto peer : membership().all_replicas()) {
      if (peer != me_ && leader_.followers.count(peer) == 0) {
        // Same as in MaybeBecomeLeader:
        leader_.followers[peer] = {
          .next_idx = log_->next_idx(),
          .send_probe = true,
          .send_heartbeat = true,
          // We set this to a number high enough that we won't immediately add
          // this replica to the set of voting replicas, and low enough that we
          // won't immediately kick them for being unresponsive.
          .last_seen_ticks = config_.election_ticks(),
        };
      }
    }
    // We probably don't need to remove followers from this leader, but
    // it keeps our followers==all_replicas story intact, so it seems
    // safer to do it.
    for (auto iter = leader_.followers.begin(); iter != leader_.followers.end(); ) {
      if (membership().all_replicas().count(iter->first) == 0) {
        iter = leader_.followers.erase(iter);
      } else {
        ++iter;
      }
    }
  }
  LOG(INFO) << "Membership change";
  for (auto peer : membership().all_replicas()) {
    LOG(INFO) << "* " << peer << (membership().voting_replicas().count(peer) ? " (voting)" : "");
  }
}

// \* Computes the hash chain value. hash is modeled in TLA+ as a random function
// \* and the value is set on first call for an input.
//           hashInput == [ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ]
//           hashValue == IF [ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ] \in DOMAIN hash THEN
//                           hash[[ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ]]
//                       ELSE
//                            RandomElement(BitString256)
std::array<uint8_t, 32> Raft::NextHash(const LogEntry& next_entry) {
  std::array<uint8_t, 32> previous_hash = {0};
  log_->MostRecentHash(&previous_hash);

  //hash the term and index into the chain along with the contents
  LogIdx next_idx = log_->next_idx();
  TermId term = next_entry.term();
  std::array<uint8_t, 16> idx_term_data {0};
  util::BigEndian64Bytes(next_idx, idx_term_data.data());
  util::BigEndian64Bytes(term, idx_term_data.data()+8);
  auto idx_term = util::ByteArrayToString(idx_term_data);

  // We add prefixes to each input, so that inputs with the same serialization are distinct.
  switch (next_entry.inner_case()) {
    case LogEntry::kData:
      return hmac::HmacSha256(previous_hash, "\001" + idx_term + next_entry.data());
    case LogEntry::kMembershipChange: {
      std::string serialized = next_entry.membership_change().SerializeAsString();
      return hmac::HmacSha256(previous_hash, "\002" + idx_term + serialized);
    }
    case LogEntry::kMinimums: {
      std::string serialized = next_entry.minimums().SerializeAsString();
      return hmac::HmacSha256(previous_hash, "\004" + idx_term + serialized);
    }
    case LogEntry::INNER_NOT_SET:
      return hmac::HmacSha256(previous_hash, "\003" + idx_term);
  }
}

// \* Leader i receives a client request to add v to the log.
std::pair<LogLocation, error::Error> Raft::ClientRequestInternal(LogEntry* entry) {
  // ClientRequest(i, v) ==
  // /\ LET entry == [term  |-> currentTerm[i],
  entry->set_term(current_term_);
  //                  value |-> v]
  // Set up hash chain for entry (TLA+ is at `NextHash` definition):
  auto new_hash = NextHash(*entry);
  //                   hashChain |-> hash[hashInput],
  entry->set_hash_chain(util::ByteArrayToString(new_hash));
  // /\ state[i] = Leader
  if (role_ != internal::Role::LEADER || leader_.relinquishing) {
    return std::make_pair(LogLocation(), COUNTED_ERROR(Raft_AppendEntryNotLeader));
  }
  //        newLog == Append(log[i], entry)
  return LogAppend(*entry);
  //    IN  log' = [log EXCEPT ![i] = newLog]
}

std::pair<LogLocation, error::Error> Raft::ClientRequest(context::Context* ctx, const std::string& data) {
  auto entry = ctx->Protobuf<LogEntry>();
  *entry->mutable_data() = data;
  auto out = ClientRequestInternal(entry);
  MaybeChangeStateAndSendMessages(ctx);
  return out;
}

std::pair<LogLocation, error::Error> Raft::ReplicaGroupChange(context::Context* ctx, const ReplicaGroup& g) {
  // We will check role again in ClientRequestInternal, but we
  // do some checks here that assume leadership, so check here
  // before we do those.
  if (role_ != internal::Role::LEADER || leader_.relinquishing) {
    MELOG(VERBOSE) << "received ReplicaGroupRequest but not leader";
    return std::make_pair(LogLocation(), COUNTED_ERROR(Raft_AppendEntryNotLeader));
  }
  // We allow only one uncommitted membership change within uncommitted
  // logs.  If we already have one, reject this request.
  if (uncommitted_memberships_.size()) {
    return std::make_pair(LogLocation(), COUNTED_ERROR(Raft_MembershipAlreadyChanging));
  }
  // Is this change actually valid?
  auto [next, err] = Membership::FromProto(g);
  if (err != error::OK) {
    return std::make_pair(LogLocation(), err);
  }
  // Does this change do anything detrimental, like remove the voting rights
  // of the current leader, emptying out all voters, etc?
  err = Membership::ValidProgressionForLeader(me_, *membership_, *next, super_majority_);
  if (err != error::OK) {
    return std::make_pair(LogLocation(), err);
  }
  // If we're here, we're going to attempt to move forward with this request.
  auto entry = ctx->Protobuf<LogEntry>();
  *entry->mutable_membership_change() = g;
  LOG(VERBOSE) << "Requesting raft membership change";
  auto out = ClientRequestInternal(entry);
  MaybeChangeStateAndSendMessages(ctx);
  return out;
}

// \* Leader i advances its commitIndex.
// \* This is done as a separate step from handling AppendEntries responses,
// \* in part to minimize atomic regions, and in part so that leaders of
// \* single-server clusters are able to mark entries committed.
void Raft::MaybeAdvanceCommitIndex(context::Context* ctx) {
  // AdvancePromiseIndex(i) ==
  // /\ state[i] = Leader
  if (role_ != internal::Role::LEADER) { return; }

  // /\ LET \* The set of servers that agree up through index.
  //        Agree(index) == {i} \cup {k \in Server :
  //                                      matchIndex[i][k] >= index}
  //        \* The maximum indexes for which a quorum agrees
  //        agreeIndexes == {index \in 1..Len(log[i]) :
  //                             Agree(index) \in Quorum}
  //        \* New value for commitIndex'[i]
  //        newPromiseIndex ==
  //           IF /\ agreeIndexes /= {}
  //              /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
  //           THEN
  //               Max(agreeIndexes)
  //           ELSE
  //               promiseIndex[i]
  //    IN /\ promiseIndex' = [promiseIndex EXCEPT ![i] = newPromiseIndex]
  std::vector<LogIdx> stored;
  std::vector<LogIdx> promised;
  for (auto [peer, replication_state] : leader_.followers) {
    if (membership().voting_replicas().count(peer)) {
      stored.push_back(replication_state.match_idx);
      promised.push_back(replication_state.promise_idx);
    }
  }
  // Sort descending, so that stored[N-1] contains the highest index
  // agreed upon by N replicas.
  stored.push_back(log_->last_idx());
  std::sort(stored.begin(), stored.end(), [](uint64_t a, uint64_t b){ return a > b; });
  LogIdx new_promise = stored[membership_quorum_size()-1];  // -1 because zero-indexed
  bool changed = false;
  if (new_promise > promise_idx_) {
    LOG(VERBOSE) << "promising logs " << promise_idx_ << " to " << new_promise;
    COUNTER(raft, logs_promised)->IncrementBy(new_promise - promise_idx_);
    promise_idx_ = new_promise;
    GAUGE(raft, promise_index)->Set(promise_idx_);
    changed = true;
  }
  // Don't push promise_idx_ until here, because we may update it above.
  // This matters for size-1 raft groups.
  promised.push_back(promise_idx_);
  // AdvanceCommitIndex(i) ==
  // /\ state[i] = Leader \* we already know that we are leader due to check above.
  //  /\ LET \* The set of servers that agree up through index.
  //     Agree(index) == {i} \cup {k \in Server :
  //                                   ackedPromiseIndex[i][k] >= index}
  //     \* The maximum indexes for which a quorum agrees
  //     agreeIndexes == {index \in 1..Len(log[i]) :
  //                         Agree(index) \in Quorum}
  //     \* New value for commitIndex'[i]
  //     newCommitIndex ==
  //       IF /\ agreeIndexes /= {}
  //           /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
  //       THEN
  //           Max(agreeIndexes)
  //       ELSE
  //           commitIndex[i]
  //     newCommittedLog ==
  //       IF newCommitIndex > 1 THEN 
  //           [ j \in 1..newCommitIndex |-> log[i][j] ] 
  //       ELSE 
  //             << >>
  // IN /\ commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
  std::sort(promised.begin(), promised.end(), [](uint64_t a, uint64_t b){ return a > b; });
  LogIdx new_commit = promised[membership_quorum_size()-1];  // -1 because zero-indexed
  if (new_commit > commit_idx_) {
    LOG(VERBOSE) << "committing logs " << commit_idx_ << " to " << new_commit;
    COUNTER(raft, logs_committed)->IncrementBy(new_commit - commit_idx_);
    commit_idx_ = new_commit;
    GAUGE(raft, commit_index)->Set(commit_idx_);
    // Committing the log has the potential to commit a previously uncomitted
    // membership; check that:
    MaybeChangeUncommittedMembershipsBasedOnLog();
    changed = true;
  }
  if (changed) {
    // The following line departs slightly from the Raft protocol, erring
    // on sending more remote messages in order to keep Raft followers more
    // up to date with the LEADER's commit.  In stock Raft, the leader is
    // the only member of the replica group whose database commits "matter"
    // in terms of latency.  For example, in an otherwise quiescent cluster,
    // if the leader gets a write, it will send that write to followers, get
    // back acknowledgements, then commit it locally.  But followers won't
    // hear about that commit until the leader's next heartbeat, which for
    // us is >= 1 tick and could be ~1s or more.  Also for us, commits matter
    // to followers, since we serve client requests from all replicas,
    // and we serve those requests by watching the commit log.
    // In practice in an active cluster, this should actually not send
    // any more messages than normal, since our (also non-Raft-standard)
    // `inflight` stops us from sending out an additional heartbeat to a
    // follower while an existing AppendEntries is in flight, and with cluster
    // activity we should expect a new log to appear at or before when we
    // would clear `inflight` and actually send this heartbeat.  But this
    // makes understanding and testing out cluster activity much easier, and
    // in cases where we do have lulls in traffic, it should keep client latency
    // low.
    //
    // TLDR:  when we update commits, we queue up a send_heartbeat for
    // all followers in order to allow them to advance their commits without
    // waiting for the next TimerTick.
    for (auto iter = leader_.followers.begin(); iter != leader_.followers.end(); ++iter) {
      iter->second.send_heartbeat = true;
    }
  }
}

//
// \* Message handlers
// \* i = recipient, j = sender, m = message
//

// \* Server i receives a RequestVote request from server j with
// \* m.mterm <= currentTerm[i].
void Raft::HandleVoteRequest(context::Context* ctx, const TermId& msg_term, const VoteRequest& msg, const peerid::PeerID& from) {
  // HandleRequestVoteRequest(i, j, m) ==
  LogIdx last_log_idx = log_->last_idx();
  TermId last_log_term = log_->last_term();
  // LET logOk ==
  //     \/ m.mlastLogTerm > LastTerm(log[i])
  //     \/ /\ m.mlastLogTerm = LastTerm(log[i])
  //        /\ m.mlastLogIndex >= Len(log[i])
  //        \* Signal TLA+ addition, guaranteed by `ValidateReceivedMessages`
  //        /\ \/ m.mlastLogIndex > Len(log[i])
  //           \/ /\ m.mlastLogIndex = Len(log[i])
  //              /\ m.mlastLogHashChain = log[i][m.mlastLogIndex].hashChain
  bool log_ok =
      msg.last_log_term() > last_log_term || (
          msg.last_log_term() == last_log_term &&
          msg.last_log_idx() >= last_log_idx);
  // LET grant ==
  //     /\ m.mterm = currentTerm[i]
  //     /\ logOk
  //     /\ votedFor[i] \in {Nil, j}
  bool grant =
      msg_term == current_term_ &&
      log_ok &&
      (!voted_for_.has_value() || *voted_for_ == from);
  // IN /\ m.mterm <= currentTerm[i]
  if (msg_term > current_term_) { return; }
  //    /\ \/ grant  /\ votedFor' = [votedFor EXCEPT ![i] = j]
  //       \/ ~grant /\ UNCHANGED votedFor
  if (grant) {
    voted_for_ = from;
    LOG(INFO) << "granted vote at " << current_term_ << " with " << last_log_idx << " at " << last_log_term << " for node " << from << " with " << msg.last_log_idx() << " at " << msg.last_log_term();
    // if we're a follower, reset our election ticks.
    follower_.election = RandomElectionTimeout();
  } else if (msg_term != current_term_) {
    LOG(INFO) << "ignored vote request with " << msg_term << " < current " << current_term_;
  } else if (voted_for_.has_value()) {
    LOG(INFO) << "rejected vote at " << current_term_ << " for node " << from << " as already voted for " << voted_for_->DebugString();
  } else {
    LOG(INFO) << "rejected vote at " << current_term_ << " with " << last_log_idx << " at " << last_log_term << " for node " << from << " at " << msg_term << " with " << msg.last_log_idx() << " at " << msg.last_log_term();
  }
  // /\ Reply([
  auto resp = ctx->Protobuf<RaftMessage>();
  resp->set_group(group_);
  //           mterm        |-> currentTerm[i],
  resp->set_term(current_term_);
  //           mtype        |-> RequestVoteResponse,
  auto vote_resp = resp->mutable_vote_response();
  //           mvoteGranted |-> grant,
  vote_resp->set_vote_granted(grant);
  AddSendableMessage(SendableRaftMessage::Reply(from, resp));
}

// \* Server i receives a RequestVote response from server j with
// \* m.mterm = currentTerm[i].
void Raft::HandleVoteResponse(context::Context* ctx, const TermId& msg_term, const VoteResponse& msg, const peerid::PeerID& from) {
  // HandleRequestVoteResponse(i, j, m) ==
  // /\ m.mterm = currentTerm[i]
  if (msg_term != current_term_) { return; }
  if (role_ != internal::Role::CANDIDATE) { return; }
  if (msg.vote_granted()) {
    if (membership().voting_replicas().count(from)) {
      // /\ \/ /\ m.mvoteGranted
      //       /\ votesGranted' = [votesGranted EXCEPT ![i] = votesGranted[i] \cup {j}]
      candidate_.votes_granted.insert(from);
      MELOG(VERBOSE) <<  "accepted vote from " << from;
    } else {
      MELOG(VERBOSE) << "ignored vote from non-voting member " << from;
    }
  } else {
    //    \/ /\ ~m.mvoteGranted /\ UNCHANGED <<votesGranted, voterLog>>
    MELOG(INFO) << "received vote rejected from " << from << " at " << current_term_;
  }
}

// \* Server i receives an AppendEntries request from server j with
// \* m.mterm <= currentTerm[i]. This just handles m.entries of length 0 or 1, but
// \* implementations could safely accept more by treating them the same as
// \* multiple independent requests of 1 entry.
void Raft::HandleAppendRequest(context::Context* ctx, const TermId& msg_term, const AppendRequest& msg, const peerid::PeerID& from) {
  uint64_t prev_log_idx = msg.prev_log_idx();
  uint64_t msg_prev_log_term = msg.prev_log_term();
  auto our_prev_log = log_->At(prev_log_idx);
  uint64_t our_prev_log_term = our_prev_log.Term();

  // We have some guarantees here since we have called `ValidateReceivedMessage` first.
  // 1. msg.prev_log_idx() >= log_.oldest_stored_idx() so our_prev_log is invalid if and only if
  //    msg.prev_log_idx() > log_.last_stored_idx(). In this case we must set logOk to false.
  // 2. If our_prev_log.Valid() then it's hash matches msg.prev_log_hash_chain()
  // 3. If any entries in msg.entries() have an index that we already have, then either
  //    a. its hash chain matches the hash chain we have at the same index (and hence the whole
  //       matches.)
  //    b. it's an old message for an old term that will be ignored
  //    c. The entry has a higher term than the one in our log, and the one in our log has
  //       not been promised, so the new entry will replace the existing one.
  // 4. msg.leader_commit() and msg.leader_promise() are less than or equal to the length of our 
  //    log after we append these.
  // 5. msg.leader_commit() >= msg.leader_promise()
  //
  // We still need to check theRaft logOk conditions and validate the hash chain on
  // all new entries.


  
  // LET logOk == \/ m.mprevLogIndex = 0
  //              \/ /\ m.mprevLogIndex > 0 
  //                 /\ m.mprevLogIndex <= Len(log[i]) \* Implied by our_prev_log.Valid(), see (1) in above comment
  //                 /\ m.mprevLogTerm = log[i][m.mprevLogIndex].term
  //                 \* Signal TLA+ extension follows
  //                 /\ m.mprevLogHash = log[i][m.mprevLogIndex].hash \* True by (2) in above comment.
  //                  /\ \/ /\ Len(m.mentries) = 0
  //                        /\ UNCHANGED hash
  //                     \/ /\ m.mprevLogIndex < Len(log[i]) \* (3) above ensures no conflict on promised values
  //                        /\ UNCHANGED hash
  //                        /\ \/ m.mentries[1].hashChain = log[i][m.mprevLogIndex+1].hashChain
  //                           \/ \* there's a conflict on a non-promised entry
  //                              /\ Len(m.mentries) > 0
  //                              /\ log[i][m.mprevLogIndex+1].term /= m.mentries[1].term
  //                              /\ promiseIndex[i] < Len(log[i])
  // \* Divergence from TLA+: Check on hash chain of appended entries is checked below,
  // \*  inconsitent hash chain still results in failure to append.
  bool log_ok = prev_log_idx == 0 || (our_prev_log.Valid() &&  msg_prev_log_term == our_prev_log_term);
      
  // IN /\ m.mterm <= currentTerm[i]
  //    /\ \/ \* return to follower state
  if (msg_term > current_term_) { return; }

  if (msg_term == current_term_) {
    //          /\ m.mterm = currentTerm[i]
    switch (role_) {
      case internal::Role::CANDIDATE: {
        //          /\ state[i] = Candidate
        //          /\ state' = [state EXCEPT ![i] = Follower]
        SetRole(internal::Role::FOLLOWER);
        follower_ = {
          .leader = from,
          .election = RandomElectionTimeout(),
        };
        MELOG(INFO) << "dropped candidacy, became follower at " << current_term_ << " of " << from;
      } break;
      case internal::Role::FOLLOWER:
        if (!follower_.leader.has_value()) {
          MELOG(INFO) << "became follower at " << current_term_ << " of " << from;
        }
        follower_.leader = from;
        follower_.election = RandomElectionTimeout();
        break;
      case internal::Role::LEADER:
        return;
    }
  }
  //       \/ /\ \* reject request
  //             \/ m.mterm < currentTerm[i]
  //             \/ /\ m.mterm = currentTerm[i]
  //                /\ state[i] = Follower
  //                /\ \lnot logOk
  if (msg_term < current_term_ || (
      msg_term == current_term_ &&
      role_ == internal::Role::FOLLOWER &&
      !log_ok)) {
    LogIdx our_last_idx = log_->last_idx();
    if (msg_term < current_term_) {
      LOG(INFO) << "ignored message with term " << msg_term << " < current " << current_term_;
    } else if (our_prev_log_term > 0) {
      LOG(WARNING) << "rejected append from " << from << " with idx " << prev_log_idx << " at term " << msg_prev_log_term << ", we have " << our_prev_log_term;
    } else {
      LOG(INFO) << "rejected append from " << from << " with idx " << prev_log_idx << ", we are behind at " << our_last_idx;
    }

    //                /\ Reply([
    auto out = ctx->Protobuf<RaftMessage>();
    out->set_group(group_);
    //                          mterm           |-> currentTerm[i],
    out->set_term(current_term_);
    //                          mtype           |-> AppendEntriesResponse,
    auto append = out->mutable_append_response();
    //                          msuccess        |-> FALSE,
    append->set_success(false);
    //                          mmatchIndex     |-> 0,
    // We send our commit index as the last index we know we matched.  If we committed
    // up to a point in time, we know we match with the rest of the Raft group up to
    // that index, so this should be safe.
    append->set_match_idx(commit_idx_);
    auto iter = log_->At(commit_idx_);
    append->set_match_hash_chain(iter.Valid() ? iter.Entry()->hash_chain() : "");
    append->set_last_log_idx(our_last_idx);
    //                          mackedPromiseIndex     |-> 0,
    // This diverges from the TLA+, but HandleAppendEntriesResponse ignores this value
    // when processing a message with success == false.
    append->set_promise_idx(promise_idx_);
    AddSendableMessage(SendableRaftMessage::Reply(from, out));
    return;
  }
  //       \/ \* accept request
  //          /\ m.mterm = currentTerm[i]
  //          /\ state[i] = Follower
  //          /\ logOk
  // ... and the TLA+ that follows doesn't correspond to procedural code well
  // find point of log conflict
  CHECK(msg_term == current_term_);
  CHECK(role_ == internal::Role::FOLLOWER);
  CHECK(log_ok);
  uint64_t last_processed_idx = prev_log_idx;
  for (int i = 0; i < msg.entries_size(); i++) {
    uint64_t msg_entry_log_idx = prev_log_idx + i + 1;
    const LogEntry& msg_entry = msg.entries(i);
    TermId our_idx_term = log_->At(msg_entry_log_idx).Term();
    if (our_idx_term != 0 && our_idx_term != msg_entry.term()) {
      if (msg_entry_log_idx <= commit_idx_) {
        LOG(WARNING) << "mismatch prior to commit: " << msg_entry_log_idx << " <= " << commit_idx_;
        break;
      } else if (msg_entry_log_idx <= promise_idx_) {
        LOG(WARNING) << "mismatch prior to promise: " << msg_entry_log_idx << " <= " << promise_idx_;
        break;
      } else if (error::OK != log_->CancelFrom(msg_entry_log_idx)) {
        LOG(WARNING) << "failed to cancel logs from " << msg_entry_log_idx;
        break;
      }
      // CancelFrom(msg_entry_log_idx) has the potential to chop off an
      // uncommitted membership from the end of the log; check that:
      MaybeChangeUncommittedMembershipsBasedOnLog();
      // If this succeeds, the next if statement should always be true.
    }

    LogIdx last = log_->last_idx();
    // If the entry is at an index that already exists in our log, then `ValidateReceivedMessages`
    // has already checked that the hash chain is consistent. On the other hand, if
    // this is a new entry then we will have `msg_entry_log_idx == last + 1`
    if (msg_entry_log_idx == last + 1) {
      auto next_hash = NextHash(msg_entry);
      // \* This fragment is part of the `logOk` definition in TLA+
      //                     \/ /\ m.mprevLogIndex = Len(log[i])
      //                        /\ m.mentries[1].hashChain = hashValue
      //                        /\ hash' = [hash EXCEPT ![hashInput] = hashValue]
      if (!util::ConstantTimeEquals(next_hash, msg_entry.hash_chain())) {
        LOG(WARNING) << "failed to append log: hash chain mismatch at " << msg_entry_log_idx;
        break;
      }
      auto [loc, err] = LogAppend(msg_entry);
      if (err != error::OK) {
        LOG(WARNING) << "failed to append log " << msg_entry_log_idx;
        break;
      } else {
        LOG(VERBOSE) << "appended log index " << msg_entry_log_idx;
      }
    }
    last_processed_idx = msg_entry_log_idx;
  }

  LogIdx leader_commit = std::min(msg.leader_commit(), last_processed_idx);
  LogIdx leader_promise = std::min(msg.leader_promise(), last_processed_idx);
  LOG(DEBUG) << "commit=" << leader_commit << " lcommit=" << msg.leader_commit()
             << " promise=" << leader_promise << " lpromise=" << msg.leader_promise()
             << " last=" << last_processed_idx;
  // TLA+... and we're back!
  // /\ commitIndex' = [commitIndex EXCEPT ![i] = m.mcommitIndex]
  bool update_merkle = false;
  if (leader_commit > commit_idx_ || leader_promise > promise_idx_) {
    if (auto err = VerifyMerkleTree(ctx); err != error::OK) {
      LOG(ERROR) << "VerifyMerkleTree failed in HandleAppendEntriesResponse: " << err;
      return;
    }
    update_merkle = true;
  }
  if (leader_commit > commit_idx_) {
    LOG(VERBOSE) << "committed transactions from " << commit_idx_ << " to " << leader_commit;
    COUNTER(raft, logs_committed)->IncrementBy(leader_commit - commit_idx_);
    commit_idx_ = leader_commit;
    GAUGE(raft, commit_index)->Set(commit_idx_);
    // Updating the commit index has the potential to commit an uncommitted
    // membership; check that:
    MaybeChangeUncommittedMembershipsBasedOnLog();
  }
  if (leader_promise > promise_idx_) {
    LOG(VERBOSE) << "promised transactions from " << promise_idx_ << " to " << leader_promise;
    COUNTER(raft, logs_promised)->IncrementBy(leader_promise - promise_idx_);
    promise_idx_ = leader_promise;
    GAUGE(raft, promise_index)->Set(promise_idx_);
  }
  if (update_merkle) {
    UpdateMerkleTree(ctx);
  }

  auto out = ctx->Protobuf<RaftMessage>();
  // /\ Reply([
  out->set_group(group_);
  //           mterm           |-> currentTerm[i],
  out->set_term(current_term_);
  //           mtype           |-> AppendEntriesResponse,
  auto append = out->mutable_append_response();
  //           msuccess        |-> TRUE,
  append->set_success(true);
  //           mmatchIndex     |-> m.mprevLogIndex + Len(m.mentries),
  append->set_match_idx(last_processed_idx);
  //           mmatchHash      |-> log[i][m.mprevLogIndex + Len(m.mentries)].hashChain,
  append->set_match_hash_chain(log_->At(last_processed_idx).Valid() ? log_->At(last_processed_idx).Entry()->hash_chain() : "");

  // The only way that last_processed_idx could be less than promise_idx_ is
  // if the leader sent inconsistent log entries at indexes we already had.
  // In this case we only tell the leader that we promise the consistent ones
  // and importantly we do not promise beyond what we have succesfully processed.
  //           mpromiseIndex   |-> m.mpromiseIndex,
  append->set_promise_idx(std::min(promise_idx_, last_processed_idx));
  append->set_last_log_idx(log_->last_idx());
  AddSendableMessage(SendableRaftMessage::Reply(from, out));
}

void Raft::MaybeChangeUncommittedMembershipsBasedOnLog() {
  bool changed = false;
  // We may have committed some of the previously uncommitted membership
  // changes by moving the commit index forward; pop them off the front.
  while (uncommitted_memberships_.size() > 0
      && uncommitted_memberships_.front().first <= commit_idx_) {
    auto f = uncommitted_memberships_.begin();
    LOG(VERBOSE) << "promoting committed membership at " << f->first;
    membership_ = std::move(f->second);
    uncommitted_memberships_.pop_front();
    changed = true;
  }
  // We may have rolled back the log via CancelFrom, chopping some
  // uncommitted memberships off the back.  Remove them.
  while (uncommitted_memberships_.size() > 0
      && uncommitted_memberships_.back().first > log_->last_idx()) {
    LOG(VERBOSE) << "discarding Uncommitted membership at " << uncommitted_memberships_.back().first;
    uncommitted_memberships_.pop_back();
    changed = true;
  }
  // If we've changed our uncommitted memberships in any way
  // that may have affected the active membership we should use,
  // handle those changes.
  if (changed) { HandleMembershipChange(); }
}

// \* Server i receives an AppendEntries response from server j with
// \* m.mterm = currentTerm[i].
void Raft::HandleAppendResponse(context::Context* ctx, const TermId& msg_term, const AppendResponse& msg, const peerid::PeerID& from) {
  
  
  // HandleAppendEntriesResponse(i, j, m) ==
  // /\ m.mterm = currentTerm[i]
  if (msg_term != current_term_) { return; }
  if (role_ != internal::Role::LEADER) { return; }
  if (leader_.followers.count(from) == 0) { return; }
  internal::ReplicationState& replication = leader_.followers[from];
  if (msg.success()) {
    // /\ \/ /\ m.msuccess \* successful
    if (replication.inflight.has_value() && msg.match_idx() >= (*replication.inflight)) {
      replication.inflight.reset();
    }
    auto match_log = log_->At(msg.match_idx());
    // We have some guarantees here since we have called `ValidateReceivedMessage` first.
    // 1. msg.match_idx() <= log_->last_idx() && msg.match_idx() >= log_.oldest_Stored_idx()
    //    thus match_log is Valid.
    // 2. msg.match_hash_chain() matches match_log.Entry()->hash_chain()
    // Thus the CHECK in the `if` branch below will always pass and the
    // `else` branch is unreachable. We leave them in for the explanation
    // of the comments and alignment with the TLA+. 
    if(match_log.Valid()) {
      // This CHECK will only fail if this server has been rolled back:
      // The follower that sent this message appended it to its log at some earlier
      // time. When it appended this entry it confirmed that the hash chain
      // value the leader sent for the entry was consistent with its own log. We
      // can use this to prove that after the follower appended this entry, its
      // log was a prefix of the leader's log when the leader sent the message.
      //    * If this was the leader that sent the message then this leader used
      //      to have a different entry in its log at msg.match_idx(). We can prove
      //      that the leader's log grows monotonically during its term unless there
      //      was a rollback. So the leader - this server - was rolled back. 
      //    * A different leader sent the log at msg.match_idx(). Since we are in
      //      a branch where msg.success() == true this could only happen one way: the
      //      follower's entry last_processed_idx had a hash chain that matched the hash
      //      chain in the AppendEntriesRequest that caused this response. That
      //      AppendEntriesRequest was sent by this server and reflected the state of this
      //      server's log at the time it was sent. Again, this means that this server's log
      //      entry at msg.match_idx() has changed.
      //      So this server has been rolled back.
      CHECK(util::ConstantTimeEquals(msg.match_hash_chain(), match_log.Entry()->hash_chain()));
    } else {
      // The following check will only fail if *this* server has been rolled back:
      // We can prove that there is only one leader per term, this is the leader
      // of that term, and this leader must have sent the entry at
      // msg.match_idx() (even if msg has entries from an earlier term). This
      // means the leader used to have a longer log! We can prove that the only
      // way a leader's log can get shorter in its term is if it has been rolled
      // back. Therefore in this situation we know that this server, the leader
      // of this term, has been rolled back.
      CHECK(msg.match_idx() <= log_->last_idx());
      // The matching index is not present in our log. This could happen for a follower that is 
      // far behind during correct execution. Because these logs are gone, this 
      // leader can never get the follower caught up.
      LOG(WARNING) << "Match idx " << msg.match_idx() << " for follower " << from << " is not present in leader's log. Cannot compare hash chain values.";
    }
    if (msg.match_idx() + 1 > replication.next_idx) {
      //       /\ nextIndex'  = [nextIndex  EXCEPT ![i][j] = m.mmatchIndex + 1]
      replication.next_idx = msg.match_idx() + 1;
    }
    if (msg.match_idx() > replication.match_idx) {
      //       /\ matchIndex' = [matchIndex EXCEPT ![i][j] = m.mmatchIndex]
      replication.match_idx = msg.match_idx();
    }
    if (msg.promise_idx() > replication.promise_idx) {
      //       /\ ackedPromiseIndex' = [ackedPromiseIndex EXCEPT ![i][j] = m.mpromiseIndex]
      replication.promise_idx = msg.promise_idx();
    }
    replication.send_probe = false;
    return;
  }
  //    \/ /\ \lnot m.msuccess \* not successful
  if (replication.send_probe) {
    LOG(VERBOSE) << "received probe append rejection at " << replication.next_idx << " from " << from << " having " << msg.last_log_idx();
  } else {
    LOG(INFO) << "received append rejection at " << replication.next_idx << " from " << from << " having " << msg.last_log_idx();
  }
  //       /\ nextIndex' = [nextIndex EXCEPT ![i][j] = Max({nextIndex[i][j] - 1, 1})]
  replication.next_idx = std::max(
      msg.match_idx() + 1,
      std::min(
          replication.next_idx - 1,
          msg.last_log_idx() + 1));
  replication.send_probe = true;
  replication.inflight.reset();
  uint64_t chunk_size_remaining = config_.replication_chunk_bytes();
  const uint64_t overflow = (uint64_t(0)) - 1; 
  for (uint64_t next_idx = replication.next_idx - 1; next_idx != overflow; next_idx--) {
    if (next_idx <= msg.match_idx()) { break; }
    size_t log_entry_size = log_->At(replication.next_idx).SerializedSize();
    if (log_entry_size > chunk_size_remaining) { break; }
    chunk_size_remaining -= log_entry_size;
    replication.next_idx = next_idx;
  }
}

void Raft::AddSendableMessage(SendableRaftMessage msg) {
  if (msg.to().has_value()) {
    // Make sure we're not looping messages
    CHECK(*msg.to() != me_);
  } else {
    // Don't bother adding a broadcast message if we're the only one in the group.
    if (membership().all_replicas().size() == 1 && membership().all_replicas().count(me_)) {
      return;
    }
  }
  sendable_messages_.push_back(msg);
}

// \* Any RPC with a newer term causes the recipient to advance its term first.
void Raft::UpdateTerm(const peerid::PeerID& from, const RaftMessage& msg) {
  // UpdateTerm(i, j, m) ==
  // /\ m.mterm > currentTerm[i]
  if (msg.term() <= current_term_) { return; }
  LOG(INFO) << "becoming follower at " << msg.term() << " (from " << current_term_ << ") due to message from " << from;
  // /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.mterm]
  COUNTER(raft, term_updated)->Increment();
  COUNTER(raft, term_increments)->IncrementBy(msg.term() - current_term_);
  current_term_ = msg.term();
  GAUGE(raft, current_term)->Set(current_term_);
  // /\ state'          = [state       EXCEPT ![i] = Follower]
  util::Ticks new_election_ticks;
  switch (role_) {
    case internal::Role::FOLLOWER:
      new_election_ticks = follower_.election;
      break;
    case internal::Role::CANDIDATE:
      new_election_ticks = candidate_.election;
      break;
    default:  // LEADER
      new_election_ticks = RandomElectionTimeout();
  }
  SetRole(internal::Role::FOLLOWER);
  follower_ = {
    .election = new_election_ticks,
  };
  // /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
  voted_for_.reset();
}

// \* Responses with stale terms are ignored.
bool Raft::ShouldDropResponseDueToStaleTerm(const peerid::PeerID& from, const RaftMessage& msg) {
  // DropStaleResponse(i, j, m) ==
  // /\ m.mterm < currentTerm[i]
  if (msg.term() < current_term_) {
    // /\ Discard(m)
    LOG(INFO) << "ignoring message with " << msg.term() << " < current " << current_term_ << " from " << from;
    return true;
  }
  return false;
}

error::Error Raft::CheckLogHash(const Log& log, LogIdx idx, TermId term, const std::string& hash, Raft::CLH_Options opts) {
  if (idx == 0) {
    return error::OK;
  }
  if (idx < log.oldest_stored_idx()) {
    return COUNTED_ERROR(Raft_MsgTruncated);
  }
  if (idx > log.last_idx()) {
    return (opts & CLH_AllowFuture) ? error::OK : COUNTED_ERROR(Raft_MsgInFuture);
  } 
  auto iter = log.At(idx);
  CHECK(iter.Valid());
  if (term == 0) {
    term = iter.Term();
  } else if (term > iter.Term()) {
    return idx > promise_idx_ ? error::OK : COUNTED_ERROR(Raft_MsgTermPromised);
  } else if (term < iter.Term()) {
    return error::OK;  // might just be an old message
  }
  if (!util::ConstantTimeEquals(hash, iter.Entry()->hash_chain())) {
    return COUNTED_ERROR(Raft_MsgHashMismatch);
  }
  return error::OK;
}

error::Error Raft::ValidateReceivedMessage(context::Context* ctx, const RaftMessage& msg, const peerid::PeerID& from) {
  if (msg.group() != group_) {
    return COUNTED_ERROR(Raft_MsgWrongGroup);
  } else if (membership().all_replicas().count(from) == 0) {
    return COUNTED_ERROR(Raft_MsgNotPeer);
  }
  switch (msg.inner_case()) {
    case RaftMessage::kVoteRequest: {
      auto m = msg.vote_request();
      RETURN_IF_ERROR(CheckLogHash(*log_,
          m.last_log_idx(),
          m.last_log_term(),
          m.last_log_hash_chain(),
          CLH_AllowFuture));
    } break;
    case RaftMessage::kVoteResponse: {
    } break;
    case RaftMessage::kAppendRequest: {
      auto m = msg.append_request();
      RETURN_IF_ERROR(CheckLogHash(*log_,
          m.prev_log_idx(),
          m.prev_log_term(),
          m.prev_log_hash_chain(),
          CLH_AllowFuture));
      if (m.leader_commit() > m.prev_log_idx() + m.entries_size()) {
        return COUNTED_ERROR(Raft_MsgAppendEntryIndex);
      }
      if (m.leader_promise() > m.prev_log_idx() + m.entries_size()) {
        return COUNTED_ERROR(Raft_MsgAppendEntryIndex);
      }
      if (m.leader_commit() > m.leader_promise()) {
        return COUNTED_ERROR(Raft_MsgLogIndexOrdering);
      }
      for (int i = 0; i < m.entries_size(); i++) {
        auto e = m.entries(i);
        RETURN_IF_ERROR(CheckLogHash(*log_,
            m.prev_log_idx() + i + 1,
            e.term(),
            e.hash_chain(),
            CLH_AllowFuture));
      }
    } break;
    case RaftMessage::kAppendResponse: {
      auto m = msg.append_response();
      RETURN_IF_ERROR(CheckLogHash(*log_,
          m.match_idx(),
          0,
          m.match_hash_chain(),
          CLH_AllowNothing));
      if (m.match_idx() > m.last_log_idx() ||
          m.promise_idx() > m.last_log_idx()) {
        return COUNTED_ERROR(Raft_MsgLogIndexOrdering);
      }
    } break;
    case RaftMessage::kTimeoutNow: {
    } break;
    case RaftMessage::INNER_NOT_SET:
    default:
      return COUNTED_ERROR(Raft_MsgInvalidType);
  }
  return error::OK;
}

// #* Receive a message.
void Raft::Receive(context::Context* ctx, const RaftMessage& msg, const peerid::PeerID& from) {
  if (auto err = ValidateReceivedMessage(ctx, msg, from); err != error::OK) {
    LOG(ERROR) << "ignoring invalid Raft message from " << from << " (" << err << "): " << MsgStr(msg);
    return;
  }
  // Receive(m) ==
  // IN \* Any RPC with a newer term causes the recipient to advance
  //    \* its term first. Responses with stale terms are ignored.
  //    \/ UpdateTerm(i, j, m)
  UpdateTerm(from, msg);
  if (role_ == internal::Role::LEADER) {
    auto f = leader_.followers.find(from);
    if (f != leader_.followers.end()) {
      f->second.last_seen_ticks = 0;
    }
  }
  switch (msg.inner_case()) {
    case RaftMessage::kVoteRequest:
      //    \/ /\ m.mtype = RequestVoteRequest
      //       /\ HandleRequestVoteRequest(i, j, m)
      COUNTER(raft, vote_requests_received)->Increment();
      LOG(VERBOSE) << "HandleVoteRequest";
      HandleVoteRequest(ctx, msg.term(), msg.vote_request(), from);
      break;
    case RaftMessage::kVoteResponse:
      //    \/ /\ m.mtype = RequestVoteResponse
      //       /\ \/ DropStaleResponse(i, j, m)
      COUNTER(raft, vote_responses_received)->Increment();
      if (ShouldDropResponseDueToStaleTerm(from, msg)) { break; }
      //          \/ HandleRequestVoteResponse(i, j, m)
      LOG(VERBOSE) << "HandleVoteResponse";
      HandleVoteResponse(ctx, msg.term(), msg.vote_response(), from);
      break;
    case RaftMessage::kAppendRequest:
      //    \/ /\ m.mtype = AppendEntriesRequest
      //       /\ HandleAppendEntriesRequest(i, j, m)
      COUNTER(raft, append_requests_received)->Increment();
      LOG(VERBOSE) << "HandleAppendRequest";
      HandleAppendRequest(ctx, msg.term(), msg.append_request(), from);
      break;
    case RaftMessage::kAppendResponse:
      //    \/ /\ m.mtype = AppendEntriesResponse
      //       /\ \/ DropStaleResponse(i, j, m)
      COUNTER(raft, append_responses_received)->Increment();
      if (ShouldDropResponseDueToStaleTerm(from, msg)) { break; }
      //          \/ HandleAppendEntriesResponse(i, j, m)
      LOG(VERBOSE) << "HandleAppendResponse";
      HandleAppendResponse(ctx, msg.term(), msg.append_response(), from);
      break;
    case RaftMessage::kTimeoutNow:
      COUNTER(raft, timeout_nows_received)->Increment();
      if (ShouldDropResponseDueToStaleTerm(from, msg)) { break; }
      LOG(VERBOSE) << "TimeoutNow";
      ElectionTimeout(ctx);
      break;
    case RaftMessage::INNER_NOT_SET:
      COUNTER(raft, invalid_requests_received)->Increment();
      LOG(ERROR) << "unhandled message case from " << from;
      break;
  }
  MaybeChangeStateAndSendMessages(ctx);
}

void Raft::MaybeChangeStateAndSendMessages(context::Context* ctx) {
  MaybeBecomeLeader(ctx);
  if (auto err = VerifyMerkleTree(ctx); err == error::OK) {
    MaybeAdvanceCommitIndex(ctx);
    UpdateMerkleTree(ctx);
  } else {
    LOG(ERROR) << "verify of merkle tree failed, refusing to advance commit index: " << err;
  }
  for (auto peer : membership().all_replicas()) {
    if (peer == me_) { continue; }
    AppendEntries(ctx, peer);
  }
  if (role_ == internal::Role::LEADER && leader_.relinquishing) {
    TryToRelinquishLeadership(ctx);
  }
}

void Raft::TryToRelinquishLeadership(context::Context* ctx) {
  bool relinquishing = false;
  peerid::PeerID next;
  for (auto peer : membership().voting_replicas()) {
    if (peer == me_) { continue; }
    auto iter = leader_.followers.find(peer);
    if (iter == leader_.followers.end()) { continue; }
    const internal::ReplicationState& state = iter->second;
    if (state.match_idx == log_->last_idx()) {
      next = peer;
      relinquishing = true;
      break;
    }
  }
  if (relinquishing) {
    // Finally, a worthy successor.  Request that it immediately execute an election timeout to
    // become the new leader.
    LOG(INFO) << "Relinquishing leadership to " << next;
    auto msg = ctx->Protobuf<RaftMessage>();
    msg->set_group(group_);
    msg->set_term(current_term_);
    msg->set_timeout_now(true);
    AddSendableMessage(SendableRaftMessage::Reply(next, msg));
    // We've relinquished leadership; become a follower at our current term.
    SetRole(internal::Role::FOLLOWER);
    follower_ = {
      .election = RandomElectionTimeout(),
    };
  }
}

util::Ticks Raft::RandomElectionTimeout() const {
  return config_.election_ticks() + rand() % config_.election_ticks();
}

std::string MsgStr(const RaftMessage& msg) {
  std::stringstream ss;
  ss << "group:" << msg.group() << " term:" << msg.term();
  switch (msg.inner_case()) {
    case RaftMessage::kVoteRequest: {
      auto m = msg.vote_request();
      ss << " vote_request:{"
         << " last_log_idx:" << m.last_log_idx()
         << " last_log_term:" << m.last_log_term()
         << " last_log_hash_chain:" << util::PrefixToHex(m.last_log_hash_chain(), 4)
         << " }";
    } break;
    case RaftMessage::kVoteResponse: {
      auto m = msg.vote_response();
      ss << " vote_response:{ vote_granted:" << m.vote_granted() << " }";
    } break;
    case RaftMessage::kAppendRequest: {
      auto m = msg.append_request();
      ss << " append_request:{ prev_log_idx:" << m.prev_log_idx()
         << " prev_log_term:" << m.prev_log_term()
         << " prev_log_hash_chain:" << util::PrefixToHex(m.prev_log_hash_chain(), 4)
         << " leader_commit:" << m.leader_commit()
         << " leader_promise:" << m.leader_promise();
      for (int i = 0; i < m.entries_size(); i++) {
        auto e = m.entries(i);
        ss << " entries:{"
           << " term=" << e.term()
           << " hash_chain=" << util::PrefixToHex(e.hash_chain(), 4)
           << " }";
      }
      ss << " }";
    } break;
    case RaftMessage::kAppendResponse: {
      auto m = msg.append_response();
      ss << " append_response:{ success:" << m.success()
         << " match_idx:" << m.match_idx()
         << " match_hash_chain:" << util::PrefixToHex(m.match_hash_chain(), 4)
         << " promise_idx:" << m.promise_idx()
         << " last_log_idx:" << m.last_log_idx() << " }";
    } break;
    case RaftMessage::kTimeoutNow: {
      ss << " timeout_now:" << msg.timeout_now();
    } break;
    case RaftMessage::INNER_NOT_SET:
      ss << "INNER_NOT_SET";
      break;
  }
  return ss.str();
}

const Membership& Raft::membership() const {
  // If we have any uncommitted memberships, use the most recent.
  if (uncommitted_memberships_.size()) {
    return *uncommitted_memberships_.back().second;
  }
  // If not, use the canonical last-committed one.
  return *membership_;
}

util::Ticks Raft::last_seen_ticks(const peerid::PeerID& follower) const {
  if (role_ != internal::Role::LEADER) { return util::InvalidTicks; }
  auto f = leader_.followers.find(follower);
  if (f == leader_.followers.end()) { return util::InvalidTicks; }
  return f->second.last_seen_ticks;
}

// Precondition: follower_id is the id of a peer in the list of followers
//               and is not this core's id.
error::Error Raft::FollowerReplicationStatus(const peerid::PeerID& follower, EnclavePeerReplicationStatus* status) const {
  CHECK(role_ == internal::Role::LEADER);
  auto f = leader_.followers.find(follower);
  if(f == leader_.followers.end()) {
    return error::OK;
  }
  status->set_next_index(f->second.next_idx);
  status->set_match_index(f->second.match_idx);
  if(f->second.inflight.has_value()) {
    status->set_inflight_index(f->second.inflight.value());
  }
  status->set_probing(f->second.send_probe);
  return error::OK;
}

static merkle::Hash MerkleHashFromLogIter(const Log::Iterator& iter) {
  if (!iter.Valid()) {
    // This will be the case when commit_idx_ or promise_idx_ is 0.
    return merkle::zero_hash;
  }
  merkle::Hash h;
  const auto& hashchain = iter.Entry()->hash_chain();
  CHECK(hashchain.size() >= h.size());
  std::copy_n(hashchain.begin(), h.size(), h.begin());
  return h;
}

void Raft::UpdateMerkleTree(context::Context* ctx) {
  MEASURE_CPU(ctx, cpu_raft_merkle_update);
  commit_leaf_.Update(MerkleHashFromLogIter(log_->At(commit_idx_)));
  promise_leaf_.Update(MerkleHashFromLogIter(log_->At(promise_idx_)));
}

error::Error Raft::VerifyMerkleTree(context::Context* ctx) {
  MEASURE_CPU(ctx, cpu_raft_merkle_verify);
  if (auto err = commit_leaf_.Verify(MerkleHashFromLogIter(log_->At(commit_idx_))); err != error::OK) {
    MELOG(ERROR) << "Merkle verify of commit failed: " << err;
    return err;
  }
  if (auto err = promise_leaf_.Verify(MerkleHashFromLogIter(log_->At(promise_idx_))); err != error::OK) {
    MELOG(ERROR) << "Merkle verify of promise failed: " << err;
    return err;
  }
  return error::OK;
}

#ifdef IS_TEST
std::unique_ptr<Raft> Raft::Copy(merkle::Tree* t) {

  // copy membership
  auto r =  std::make_unique<Raft>(
          group_,  // group
          me_,
          t,
          std::make_unique<Membership>(*membership_),
          log_->Copy(),  // 1MB log
          config_,
          false,
          super_majority_);
  // copy uncommitted_memberships_
  r->role_ = role_;
  r->follower_ =  follower_;
  r->candidate_ = candidate_;
  r->leader_ =  leader_;

  r->last_applied_ = last_applied_;
  r->current_term_ = current_term_;
  r->commit_idx_ = commit_idx_;
  r->promise_idx_ = promise_idx_;
  r->super_majority_ = super_majority_;
  context::Context ctx;
  r->UpdateMerkleTree(&ctx);
  return r;
}
#endif // IS_TEST
}  // namespace svr2::raft
