// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CORE_CORETEST_REPLICAGROUP_H__
#define __SVR2_CORE_CORETEST_REPLICAGROUP_H__

#include <algorithm>
#include <map>
#include <numeric>

#include "core/core.h"
#include "peerid/peerid.h"
#include "testingcore.h"
#include "util/macros.h"

namespace svr2::core::test {
using PartitionID = uint32_t;
using TestingCoreMap = std::map<peerid::PeerID, TestingCore *>;
using PartitionMap = std::map<peerid::PeerID, PartitionID>;
using ReversePartitionMap = std::map<PartitionID, std::vector<peerid::PeerID>>;

template <typename T>
std::pair<PartitionID, size_t> LargestPartition(
    const std::map<T, PartitionID> &partition) {
  std::map<PartitionID, size_t> counts;

  size_t max_count{0};
  PartitionID largest_partition{0};
  for (const auto &[key, val] : partition) {
    counts[val]++;
    if (counts[val] > max_count) {
      max_count = counts[val];
      largest_partition = val;
    }
  }
  return std::make_pair(largest_partition, max_count);
}

class ReplicaGroup {
  // This PartitionID represents the full replica group and is used
  // internally to override an existing partition.
  static const PartitionID FULL_GROUP_PARTITION_ID = UINT32_MAX;

 public:
  ReplicaGroup() {}
  // This is not copyable because `peers_` is not copyable
  DELETE_COPY_AND_ASSIGN(ReplicaGroup);

  const TestingCore *get_core(size_t i) const {
    CHECK(i < peers_.size());
    return peers_[i].get();
  }

  TestingCore *get_core(size_t i) {
    CHECK(i < peers_.size());
    return peers_[i].get();
  }

  TestingCore *get_leader_core() { return get_core(GroupLeaderIndex()); }
  const TestingCore *get_leader_core() const {
    return get_core(GroupLeaderIndex());
  }
  TestingCore *get_voting_nonleader_core() {
    auto peer = std::find_if(peers_.cbegin(), peers_.cend(), [](const auto &p) {
      return p->voting() && !p->leader();
    });
    return peer != peers_.cend() ? peer->get() : nullptr;
  }

  size_t partition_size(size_t i) const {
    auto id = peers_[i]->ID();
    PartitionID part_id = partition_.find(id)->second;
    return partition_members_.find(part_id)->second.size();
  }

  enclaveconfig::EnclaveConfig get_enclave_config() const {
    return enclave_config_;
  }
  enclaveconfig::InitConfig get_init_config() const {
    return init_config_;
  }

  size_t num_voting() const { return get_leader_core()->num_voting(); }

  size_t num_serving() const { return get_leader_core()->num_serving(); }

  /***
   * Creates and initializes TestingCores with given configuration. The first
   * `initial_voting` items in the returned vector will be accepted voting
   * members, the next `initial_nonvoting` will be up-to-date non-voting
   * members, and the rest will be connected non-members
   */
  void Init(enclaveconfig::InitConfig cfg,
            size_t initial_voting,
            size_t initial_nonvoting, size_t initial_nonmember);
  /**
   * @brief Check whether any replicas have messages to process
   *
   * @return true Some replica has a message to process
   * @return false No messages to process
   */
  bool IsQuiet() const;

  /**
   * @brief Get the ID of the group leader if a quorum with a leader exists.
   *
   * @return peerid::PeerID A valid ID if a quorum is possible and a leader
   * exists
   */
  peerid::PeerID GroupLeader() const {
    auto index = GroupLeaderIndex();
    return index < peers_.size() ? peers_[index]->ID() : peerid::PeerID();
  }

  /**
   * @brief Get the index of the group leader if a quorum with a leader exists.
   *
   * @return size_t SIZE_MAX if no leader is possible, index of the leader
   * otherwise.
   */
  size_t GroupLeaderIndex() const {
    auto [largest_partition, partition_size] = LargestPartition(partition_);
    auto found = std::find_if(
        peers_.cbegin(), peers_.cend(),
        [this, largest_partition = largest_partition](const auto &p) {
          return p->leader() && p->active() &&
                 partition_.find(p->ID())->second == largest_partition;
        });
    return found - peers_.cbegin();
  }
  /**
   * @brief Find ID of group leader in a peer's partition
   *
   * @param peer_id ID of peer looking for reachable leader
   * @return peerid::PeerID ID of a replica that (1) believes it is leader and
   * (2) is in same partition as peer_id OR, if not found, returns invalid
   * PeerID.
   */
  peerid::PeerID GroupLeaderInPartition(peerid::PeerID peer_id) const {
    auto found = std::find_if(peers_.cbegin(), peers_.cend(),
                              [this, peer_id](const auto &p) {
                                return p->leader() && p->active() &&
                                       partition_.find(p->ID())->second ==
                                           partition_.find(peer_id)->second;
                              });
    return found == peers_.cend() ? peerid::PeerID() : (*found)->ID();
  }
  /**
   * @brief Find index of group leader in a peer's partition
   *
   * @param peer_id ID of peer looking for reachable leader
   * @return size_t of a replica that (1) believes it is leader and (2) is
   * in same partition as peer_id OR, if not found, returns peers_.size().
   */
  size_t GroupLeaderIndexInPartition(peerid::PeerID peer_id) const {
    auto found = std::find_if(peers_.cbegin(), peers_.cend(),
                              [this, peer_id](const auto &p) {
                                return p->leader() && p->active() &&
                                       partition_.find(p->ID())->second ==
                                           partition_.find(peer_id)->second;
                              });
    return found - peers_.cbegin();
  }

  /**
   * @brief Send a message (through the `replica_group_` fabric) to a peer.
   *
   * @param to Recipient ID
   * @param msg
   * @return error::Error Error from `TestingCore::AddPeerMessage` or
   * `error::OK`.
   */
  error::Error SendMessage(peerid::PeerID to, PeerMessage msg);
  /**
   * @brief All peers in a partition process incoming messages then forward
   * resulting outgoing messages until there are no more incoming messages to
   * process
   *
   * @param pid Optional partition ID. If not provided then partitioning is
   * ignored and it applies to full group
   * @return error::Error
   */
  error::Error PassMessagesUntilQuiet(
      PartitionID pid = FULL_GROUP_PARTITION_ID);
  /**
   * @brief All peers in a partition process all responses from enclaves to
   * hosts.
   *
   * @param pid Optional partition ID. If not provided then partitioning is
   * ignored and it applies to full group
   * @return error::Error returns any error from a HostToEnclaveResponse
   */
  error::Error ProcessAllH2EResponses(
      PartitionID pid = FULL_GROUP_PARTITION_ID);
  /**
   * @brief All peers in a partition get a timer tick, process it, then forward
   * any outgoung messages
   *
   * @param pid
   * @return error::Error
   */
  error::Error TickAllTimers(PartitionID pid = FULL_GROUP_PARTITION_ID);
    /**
   * @brief Tick all timers, pass messages until quiet, and then optionally
   * check to see if any errors came back in the HostToEnclaveResponses
   *
   * @param ignore_h2e_errors
   */
  void TickTock(bool ignore_h2e_errors);
  void TickTock(PartitionID pid, bool ignore_h2e_errors);

  void CreatePartition(std::map<size_t, PartitionID> partition) {
    partition_.clear();
    partition_members_.clear();

    // map the array indices to PeerIDs
    for (auto [idx, partition_id] : partition) {
      auto peer_id = get_core(idx)->ID();
      partition_[peer_id] = partition_id;
      partition_members_[partition_id].emplace_back(peer_id);
    }
  }

  void ClearPartition() {
    partition_.clear();
    partition_members_.clear();
    for (const auto &peer : peers_) {
      partition_[peer->ID()] = 1;
      partition_members_[1].emplace_back(peer->ID());
    }
  }

  void ForwardBlockedMessages();
  void ClearBlockedMessages() { blocked_peer_messages_.clear(); }

 private:
  void add_peer();
  enclaveconfig::EnclaveConfig enclave_config_;
  enclaveconfig::InitConfig init_config_;
  std::vector<std::unique_ptr<TestingCore>> peers_;

  TestingCoreMap peers_by_id_;
  PartitionMap partition_;
  ReversePartitionMap partition_members_;
  std::map<peerid::PeerID, std::vector<PeerMessage>> blocked_peer_messages_;
};

};      // namespace svr2::core::test
#endif  // __SVR2_CORE_CORETEST_REPLICAGROUP_H__
