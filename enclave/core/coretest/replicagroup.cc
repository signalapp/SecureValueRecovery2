// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "replicagroup.h"

#include <gtest/gtest.h>

namespace svr2::core::test {

bool ReplicaGroup::IsQuiet() const {
  for (const auto& [peer_id, core] : peers_by_id_) {
    if (core->active() && core->input_messages().size() > 0) return false;
  }
  return true;
}

error::Error ReplicaGroup::SendMessage(peerid::PeerID to, PeerMessage msg) {
  peerid::PeerID from;
  from.FromString(msg.peer_id());
  PartitionID to_partition = partition_[to];
  PartitionID from_partition = partition_[from];

  if (to_partition == from_partition) {
    LOG(VERBOSE) << "#####################################################";
    LOG(VERBOSE) << "# peer message to " << to << " from " << from;
    RETURN_IF_ERROR(peers_by_id_[to]->AddPeerMessage(std::move(msg)));
  } else {
    LOG(VERBOSE) << "#---------------------------------------------------#";
    LOG(VERBOSE) << "# BLOCKED peer message to " << to << " from " << from;
    blocked_peer_messages_[to].emplace_back(std::move(msg));
  }
  return error::OK;
}

error::Error ReplicaGroup::PassMessagesUntilQuiet(PartitionID pid) {
  error::Error err = error::OK;
  while (!IsQuiet()) {
    for (auto& core : peers_) {
      if (pid == FULL_GROUP_PARTITION_ID ||
          partition_.find(core->ID())->second == pid) {
        RETURN_IF_ERROR(core->ProcessIncomingMessage());
        RETURN_IF_ERROR(core->ForwardOutgoingMessages());
      }
    }
  }
  return err;
}

error::Error ReplicaGroup::ProcessAllH2EResponses(PartitionID pid) {
  for (auto& core : peers_) {
    if (pid == FULL_GROUP_PARTITION_ID ||
        partition_.find(core->ID())->second == pid) {
      RETURN_IF_ERROR(core->ProcessAllH2EResponses());
    }
  }
  return error::OK;
}

error::Error ReplicaGroup::TickAllTimers(PartitionID pid) {
  for (auto& [peer_id, core] : peers_by_id_) {
    if (pid == FULL_GROUP_PARTITION_ID ||
        partition_.find(peer_id)->second == pid) {
      RETURN_IF_ERROR(core->TimerTick());
      RETURN_IF_ERROR(core->ProcessIncomingMessage());
    }
  }

  for (auto& [peer_id, core] : peers_by_id_) {
    if (pid == FULL_GROUP_PARTITION_ID ||
        partition_.find(peer_id)->second == pid) {
      RETURN_IF_ERROR(core->ForwardOutgoingMessages());
    }
  }
  return error::OK;
}

void ReplicaGroup::TickTock(bool ignore_h2e_errors) {
  TickTock(FULL_GROUP_PARTITION_ID, ignore_h2e_errors);
}

void ReplicaGroup::TickTock(PartitionID pid, bool ignore_h2e_errors) {
  ASSERT_EQ(error::OK, TickAllTimers(pid));
  ASSERT_EQ(error::OK, PassMessagesUntilQuiet());
  auto err = ProcessAllH2EResponses();
  if (!ignore_h2e_errors) ASSERT_EQ(error::OK, err);
}

void ReplicaGroup::add_peer() {
  peers_.emplace_back(std::make_unique<TestingCore>(*this));
  auto peer = peers_.rbegin()->get();
  peers_by_id_[peer->ID()] = peer;
}

void ReplicaGroup::Init(enclaveconfig::InitConfig cfg,
                        size_t initial_voting,
                        size_t initial_nonvoting, size_t initial_nonmember) {
  init_config_ = cfg;
  enclave_config_ = cfg.enclave_config();
  size_t num_cores = initial_voting + initial_nonvoting + initial_nonmember;
  LOG(INFO) << "ADDING " << num_cores << " PEERS";
  for (size_t i = 0; i < num_cores; ++i) {
    add_peer();
  }

  LOG(INFO) << "CREATING RAFT";
  ASSERT_EQ(error::OK, peers_[0]->CreateNewRaftGroup());
  ASSERT_EQ(error::OK, PassMessagesUntilQuiet());
  for (size_t i = 1; i < initial_voting + initial_nonvoting; ++i) {
    LOG(INFO) << "JOINING " << i << " of " << (initial_nonvoting + initial_voting);
    // request to join raft from the previous peer (so not always the leader)
    ASSERT_EQ(error::OK, peers_[i]->JoinRaft(peers_[i - 1]->ID()));
    ASSERT_EQ(error::OK, PassMessagesUntilQuiet());
    CHECK(peers_[i]->serving());
  }

  for (size_t i = 1; i < initial_voting; ++i) {
    LOG(INFO) << "VOTING " << i << " of " << initial_voting;
    ASSERT_EQ(error::OK, peers_[i]->RequestVoting());
    ASSERT_EQ(error::OK, PassMessagesUntilQuiet());
  }

  std::vector<peerid::PeerID> partition_members;
  for (const auto& peer : peers_) {
    auto peer_id = peer->ID();
    partition_[peer_id] = 1;
    partition_members.emplace_back(std::move(peer_id));
  }
  partition_members_.emplace(std::make_pair(1, partition_members));

  ASSERT_EQ(error::OK, PassMessagesUntilQuiet());
}
void ReplicaGroup::ForwardBlockedMessages() {
  for (auto&& [peer_id, msgs] : blocked_peer_messages_) {
    for (auto&& msg : msgs) {
      peerid::PeerID from;
      from.FromString(msg.peer_id());
      LOG(VERBOSE) << "#******************************************#";
      LOG(VERBOSE) << "# Forwarding blocked peer message to " << peer_id
                   << " from " << from;
      peers_by_id_[peer_id]->AddPeerMessage(std::move(msg));
    }
  }
}

};  // namespace svr2::core::test
