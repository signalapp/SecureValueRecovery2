// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CORE_CORE_H__
#define __SVR2_CORE_CORE_H__

#include <memory>
#include <mutex>
#include <atomic>
#include "proto/enclaveconfig.pb.h"
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"
#include "util/macros.h"
#include "peerid/peerid.h"
#include "peers/peers.h"
#include "context/context.h"
#include "raft/log.h"
#include "raft/raft.h"
#include "client/client.h"
#include "sip/hasher.h"
#include "db/db.h"
#include "core/internal.h"
#include "util/macros.h"
#include "util/ticks.h"
#include "timeout/timeout.h"
#include "groupclock/groupclock.h"
#include "minimums/minimums.h"

namespace svr2::core {

// Core is the core singleton of a running enclave.  Each running enclave
// should have exactly one of these, created on initialization.
class Core {
 public:
  DELETE_COPY_AND_ASSIGN(Core);

  // Receive a message from the host.
  error::Error Receive(context::Context* ctx, const UntrustedMessage& msg);

  // Peer ID for this core.
  const peerid::PeerID& ID() const { return peer_manager_->ID(); }

  // Create a core from a given config.
  static std::pair<std::unique_ptr<Core>, error::Error> Create(
      context::Context* ctx,
      const enclaveconfig::InitConfig& config);

#ifdef IS_TEST
  bool serving() const {
    util::unique_lock lock(raft_.mu);
    return raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP;
  }
  bool leader() const {
    util::unique_lock lock(raft_.mu);
    return raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP && raft_.loaded.raft->is_leader();
  }
  bool voting() const {
    util::unique_lock lock(raft_.mu);
    return raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP && raft_.loaded.raft->voting();
  }
  size_t num_voting() const {
    util::unique_lock lock(raft_.mu);
    return raft_.loaded.raft->membership().voting_replicas().size();
  }
  size_t num_members() const {
    util::unique_lock lock(raft_.mu);
    return raft_.loaded.raft->membership().all_replicas().size();
  }
  std::set<peerid::PeerID> all_replicas() const {
    util::unique_lock lock(raft_.mu);
    return raft_.loaded.raft->membership().all_replicas();
  }
#endif

 private:
  struct ReplicationPushState {
    ReplicationPushState(raft::LogIdx idx, const peerid::PeerID& to, const e2e::TransactionRequest& req)
        : logs_from_idx_inclusive(idx),
          db_from_key_exclusive(""),
          finished_sending(false),
          target(to),
          tx(req.request_id()),
          replication_id(req.replicate_state().replication_id()),
          replication_sequence(0),
          sent_response(false) {}

    raft::LogIdx logs_from_idx_inclusive;  // GUARDED_BY(raft_.mu)
    std::string db_from_key_exclusive;  // GUARDED_BY(raft_.mu)
    bool finished_sending;  // GUARDED_BY(raft_.mu)
    const peerid::PeerID target;
    const internal::TransactionID tx;
    const uint64_t replication_id;
    uint64_t replication_sequence;  // GUARDED_BY(raft_mu)
    std::atomic<bool> sent_response;
  };

  Core(const enclaveconfig::RaftGroupConfig& group_config);
  // Init this core object.  This function should be
  // called exactly once for each Core object, and sould be the first function
  // called subsequent to construction.
  error::Error Init(
      context::Context* ctx,
      const enclaveconfig::EnclaveConfig& config,
      util::UnixSecs initial_timestamp_unix_secs);

  //// Top-level callers, called by Receive(), and their subfunctions.

  // Handle a request from the host
  error::Error HandleHostToEnclave(context::Context* ctx, const HostToEnclaveRequest& msg);
    // Handle a request for a new client
    void HandleNewClient(context::Context* ctx, const NewClientRequest& msg, internal::TransactionID tx);
    // Handle a message being passed through the host to an existing client
    error::Error HandleExistingClient(context::Context* ctx, const ExistingClientRequest& msg, internal::TransactionID tx);
    // Request that we create a new raft group from scratch, setting ourselves
    // as the sole member and leader.  This should be done to seed a new
    // Raft, after which we should requst JoinRaft instead.
    void HandleCreateNewRaftGroupRequest(context::Context* ctx, internal::TransactionID tx) EXCLUDES(raft_.mu);
      // Creates a test account within the Raft DB.
      error::Error AddTestAccount(context::Context* ctx, uint32_t i);
    // Join an existing Raft group.
    void HandleJoinRaft(context::Context* ctx, const JoinRaftRequest& msg, internal::TransactionID tx) EXCLUDES(raft_.mu);
      // Given a single seed peer, connect to it and get the existing configs.
      void JoinRaftFromFirstPeer(context::Context* ctx) REQUIRES(raft_.mu);
      // Replicate all data from our existing peer(s) until we've got a full set of data.
      void RequestRaftReplication(context::Context* ctx) REQUIRES(raft_.mu);
      // Now that we've got a full set of Raft data (logs+db), set up our local Raft objects.
      void PromoteRaftToLoaded(context::Context* ctx) REQUIRES(raft_.mu);
      // Request to become a (nonvoting) member of the Raft group we have data for.
      void RaftRequestMembership(context::Context* ctx, internal::TransactionID tx) REQUIRES(raft_.mu);
    // Refresh attestations for peer and client connections.
    error::Error HandleRefreshAttestation(context::Context* ctx, bool rotate_key) EXCLUDES(raft_.mu);
    // Get the current status of this replica to be returned to the host.
    std::pair<EnclaveReplicaStatus, error::Error> HandleGetEnclaveStatus(context::Context* ctx) const EXCLUDES(raft_.mu);
    // Handle a host-requested delete of a backup ID.
    error::Error HandleHostDatabaseRequest(context::Context* ctx, internal::TransactionID tx, const DatabaseRequest& req);
    // Reconfigure the replica with new host-supplied configuration.
    error::Error HandleReconfigure(context::Context* ctx, internal::TransactionID tx, const enclaveconfig::EnclaveConfig& req) EXCLUDES(raft_.mu);
    // If we're the raft leader, give it up.
    void HandleRelinquishLeadership(context::Context* ctx, internal::TransactionID tx) EXCLUDES(raft_.mu);
    // Request that this replica be removed from the Raft group.
    void HandleHostRequestedRaftRemoval(context::Context* ctx, internal::TransactionID tx) EXCLUDES(raft_.mu);
    // Compute and return to the host a hash of the current DB.
    error::Error HandleHostHashes(context::Context* ctx, internal::TransactionID tx) EXCLUDES(raft_.mu);
    // Handle a request to update MinimumLimits.
    void HandleUpdateMinimums(context::Context* ctx, internal::TransactionID tx, const minimums::MinimumLimits& update) EXCLUDES(raft_.mu);

  // Handle the inevitable march of time.
  void HandleTimerTick(context::Context* ctx, const TimerTick& tick);
    // Update our group-based concept of time.
    void MaybeUpdateGroupTime(context::Context* ctx) EXCLUDES(raft_.mu);
    // If we're in Raft with some other replicas but don't yet have peer connections
    // to them, try to establish them.
    void ConnectToRaftMembers(context::Context* ctx) REQUIRES(raft_.mu);
    // Return either a nullptr, or a replica config (in scope [ctx]) that
    // this instance believes should be the next config for this raft group.
    raft::ReplicaGroup* NextReplicaGroup(context::Context* ctx) REQUIRES(raft_.mu);

  // Decode a new message proxied from a peer replica through our host.
  error::Error HandlePeerMessage(context::Context* ctx, const UntrustedMessage& msg);
    // Handle an EnclaveToEnclaveMessage decoded from the peer message
    error::Error HandleE2E(context::Context* ctx, const peerid::PeerID& from, const e2e::EnclaveToEnclaveMessage& msg);
      // Handle the case where we've just successfully established a connection to the peer `from`
      void HandlePeerConnect(context::Context* ctx, const peerid::PeerID& from);
      // Handle an enclave-to-enclave transaction requested by a remote peer client.
      error::Error HandleE2ETransaction(context::Context* ctx, const peerid::PeerID& from, const e2e::TransactionRequest& msg);
        // Handle a request to replicate our state (Raft DB and logs) to `from`
        error::Error HandleReplicateStateRequest(context::Context* ctx, const peerid::PeerID& from, const e2e::TransactionRequest& req) EXCLUDES(raft_.mu);
          // Send the next set of replicating state to `from`, in the form of a ReplicateStatePush E2E transaction.
          void SendNextReplicationState(context::Context* ctx, std::shared_ptr<ReplicationPushState> push_state) REQUIRES(raft_.mu);
        // Handle receipt of the next piece of state from a server that's replicating their state to us.
        error::Error HandleReplicateStatePush(context::Context* ctx, const e2e::ReplicateStatePush& push) EXCLUDES(raft_.mu);
          // Handle applying replicated state to an as-yet-unfinished Raft database (in raft_.loading.db)
          error::Error MaybeApplyLogToReplicatingDatabase(context::Context* ctx, const raft::LogEntry& entry) REQUIRES(raft_.mu);
        // Handle a request to join our Raft group.
        error::Error HandleRequestRaftMembership(context::Context* ctx, const peerid::PeerID& from, e2e::TransactionResponse* resp) EXCLUDES(raft_.mu);
        // Handle a request to become a voting member of our Raft group.
        error::Error HandleRequestRaftVoting(context::Context* ctx, const peerid::PeerID& from, e2e::TransactionResponse* resp) EXCLUDES(raft_.mu);
        // Handle a request to write a client log into our Raft group.
        error::Error HandleRaftWrite(context::Context* ctx, const std::string& data, e2e::TransactionResponse* resp) EXCLUDES(raft_.mu);
        // Handle receipt of a new timestamp supplied by `from`.
        void HandleNewTimestamp(context::Context* ctx, const peerid::PeerID& from, uint64_t unix_secs);
        // Handle a request to remove the sender from Raft.
        error::Error HandlePeerRequestedRaftRemoval(context::Context* ctx, const peerid::PeerID& from, internal::TransactionID tx) EXCLUDES(raft_.mu);

  //// Common or utility functions called by multiple handlers.

  // RaftStep handles sending any outstanding raft messages and applying
  // any committed transactions.  It should be called after any change to
  // Raft state, including receiving a raft message, requesting a client
  // log, etc.
  void RaftStep(context::Context* ctx) REQUIRES(raft_.mu);
    // Send any messages buffered by raft to our peers.
    void RaftSendMessages(context::Context* ctx) REQUIRES(raft_.mu);
    // See if any logs have been committed since last we looked, and apply them to our
    // internal state if there are some.
    void RaftHandleCommittedLogs(context::Context* ctx) REQUIRES(raft_.mu);
      // Handle a Raft log that changes group membership, which may either
      // add us to a group or remove us from our group.
      void HandleRaftMembershipChange(
          context::Context* ctx,
          raft::LogIdx idx,
          raft::TermId term,
          const raft::ReplicaGroup& membership_change) REQUIRES(raft_.mu);
      // Handle a Raft log that changes minimums.
      void HandleRaftMinimumsChange(
          context::Context* ctx,
          raft::LogIdx idx,
          raft::TermId term,
          const minimums::MinimumLimits& minimums) REQUIRES(raft_.mu);
      // Attempt to apply the committed log entry to the db::DB.  On success,
      // return a db::DB::Response (owned by [ctx]).  On failure, return
      // nullptr.  Regardless, [committed_entry] is considered to be successfully
      // committed to the database after this call.
      db::DB::Response* RaftApplyLogToDatabase(
          context::Context* ctx,
          raft::LogIdx idx,
          const raft::LogEntry& committed_entry) REQUIRES(raft_.mu);
      // HandleLogTransactionsForRaftLog handles any queued log
      // transactions in outstanding_log_transactions_ associated with the given
      // log entry.
      void HandleLogTransactionsForRaftLog(
          context::Context* ctx,
          raft::LogIdx idx,
          const raft::LogEntry& entry,
          // response may be null in the case where we failed to parse it from the Raft log.
          const db::DB::Response* response) REQUIRES(raft_.mu);

  // Send a local timestamp to remote peer `to`.
  void SendTimestamp(context::Context* ctx, peerid::PeerID to, uint64_t unix_seconds);
  // Send our local timestamp to all connected peers.
  void SendTimestampToAll(context::Context* ctx);

  static error::Error ValidateConfig(const enclaveconfig::EnclaveConfig& config);
  static error::Error ValidateConfigChange(const enclaveconfig::EnclaveConfig& old_config, const enclaveconfig::EnclaveConfig& new_config);

  mutable util::mutex config_mu_;
  enclaveconfig::EnclaveConfig enclave_config_ GUARDED_BY(config_mu_);
  const enclaveconfig::RaftGroupConfig raft_config_template_;

  minimums::Minimums minimums_;

  enclaveconfig::EnclaveConfig* enclave_config(context::Context* ctx) const EXCLUDES(config_mu_);

  std::unique_ptr<peers::PeerManager> peer_manager_;
  std::unique_ptr<client::ClientManager> client_manager_;

  // The merkle tree should only be accessed while holding raft_.mu.
  // THE SAME HOLDS TRUE FOR ALL OF ITS LEAVES.  We can't correctly
  // annotate that, but it's important, so I wrote it in capital letters.
  merkle::Tree merkle_tree_ GUARDED_BY(raft_.mu);

  internal::Raft raft_;
  const enclaveconfig::DatabaseVersion db_version_;
  const db::DB::Protocol* const db_protocol_;
  groupclock::Clock clock_;
  
  // Handle timeouts.
  timeout::Timeout timeout_;

  typedef std::function<void(
      // Context in which to run this callback.
      context::Context*,
      // Error that may have occurred disallowing this transaction from completing.
      // Will be Core_LogTransactionCancelled if this log was not the one requested.
      error::Error,
      // The committed log entry.  Null if err!=OK.
      const raft::LogEntry* entry,
      // If this log was a client request, the associated client response.
      // Null if err!=OK.
      const db::DB::Response* response)> LogTransactionCallback;
  // When we submit a transaction to the log, we get back the idx/term
  // at which it should be committed.  Later, we see that LogIdx go by, and
  // if the term matches, we're in business and can execute the transaction.
  // If the term does _not_ match, then this transaction was overridden or
  // cancelled by a Raft election.
  struct LogTransaction {
    raft::TermId term;
    LogTransactionCallback cb;
    // If the expected_hash_chain is the empty string it is ignored. Otherwise
    // if the hash_chain for this long index does not match the
    // expected_hash_chain the transaction is aborted.
    std::string expected_hash_chain;
  };
  // This is a multimap because, if the leader changes, we could possibly
  // have multiple transactions mapped to the same log index (with different
  // terms).
  util::mutex outstanding_log_transactions_mu_;
  std::unordered_multimap<raft::LogIdx, LogTransaction> outstanding_log_transactions_ GUARDED_BY(outstanding_log_transactions_mu_);
  // Adds a callback to be run when the log at the given location has been commited.
  // NOTE:  when cb is called, raft_.mu will be locked already.
  void AddLogTransaction(context::Context* ctx, const raft::LogLocation& loc, LogTransactionCallback cb) EXCLUDES(outstanding_log_transactions_mu_);
  error::Error RaftWriteLogTransaction(context::Context* ctx, raft::LogEntry* entry, LogTransactionCallback cb) EXCLUDES(raft_.mu);
  LogTransactionCallback ClientLogTransaction(context::Context* ctx, client::ClientID client_id, internal::TransactionID tx);

  // State for transactions that this enclave sends to other enclaves.
  // Transactions are kept locally as a map of callbacks (of type
  // E2ECallback).  On receipt of a response, we look for the appropriate
  // callback in the outstanding_e2e_transactions_ map and call it.
  util::mutex e2e_txn_mu_ ACQUIRED_AFTER(raft_.mu);
  internal::TransactionID e2e_txn_id_ GUARDED_BY(e2e_txn_mu_);
  typedef std::function<void(
      // Context in which to run this callback
      context::Context*,
      // Error that may have occurred disallowing this transaction from
      // completing. For example, if we were unable to encrypt correctly
      // for the associated peer, etc.
      error::Error,
      // If error==OK, the transaction response (otherwise nullptr)
      const e2e::TransactionResponse*)> E2ECallback;
  struct E2ECall {
    E2ECallback callback;
    timeout::Cancel timeout_cancel;
    peerid::PeerID to;
  };
  std::unordered_map<internal::TransactionID, E2ECall> outstanding_e2e_transactions_ GUARDED_BY(e2e_txn_mu_);
  // Send an Enclave-to-enclave transaction.
  void SendE2ETransaction(
      context::Context* ctx,
      const peerid::PeerID& to,
      const e2e::TransactionRequest& req,
      bool with_timeout,  // If false, allow to run forever.
      E2ECallback callback) EXCLUDES(e2e_txn_mu_);
  error::Error SendE2EError(context::Context* ctx, const peerid::PeerID& from, internal::TransactionID id, error::Error err);
  // Called when a peer ID reset is requested by the host.  This means that the
  // host has abandoned the peer.  In this case, we treat all transactions
  // to that host as having failed.
  error::Error ResetPeer(context::Context* ctx, const peerid::PeerID& id);
};

}  // namespace svr2::core

#endif  // __SVR2_CORE_CORE_H__
