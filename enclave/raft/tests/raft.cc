// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP peerid
//TESTDEP context
//TESTDEP hmac
//TESTDEP sip
//TESTDEP sender
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP noise-c
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "raft/raft.h"
#include "peerid/peerid.h"
#include "env/env.h"
#include "util/log.h"
#include "proto/e2e.pb.h"
#include <memory>

namespace svr2::raft {

class RaftTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init();
  }

  enclaveconfig::RaftConfig DefaultConfig() {
    enclaveconfig::RaftConfig config;
    config.set_election_ticks(5);
    config.set_heartbeat_ticks(1);
    config.set_replication_chunk_bytes(1<<20);
    config.set_replica_voting_timeout_ticks(15);
    config.set_replica_membership_timeout_ticks(30);
    return config;
  }

  void SetUpRaft(int size, enclaveconfig::RaftConfig config) {
    // Create a size-3 raft group
    ReplicaGroup g;
    std::set<peerid::PeerID> peers;
    for (int i = 0; i < size; i++) {
      uint8_t peer_id[32];
      ASSERT_EQ(error::OK, env::environment->RandomBytes(peer_id, sizeof(peer_id)));
      peerid::PeerID p(peer_id);
      auto r = g.add_replicas();
      p.ToString(r->mutable_peer_id());
      r->set_voting(true);
      peers.insert(p);
    }
    auto [mem, err] = Membership::FromProto(g);
    ASSERT_EQ(error::OK, err);
    for (auto peer : peers) {
      auto memcpy = std::make_unique<Membership>(*mem);
      auto r = std::make_unique<Raft>(
          1,  // group
          peer,
          std::move(memcpy),
          std::move(std::make_unique<Log>(1<<20)),  // 1MB log
          config,
          false,
          0);
      group_[peer] = std::move(r);
    }
  }

  void RouteMessages() {
    bool quiescent = false;
    int iter = 0;
    LOG(INFO) << "--------------------- Message routing";
    while (!quiescent) {
      LOG(INFO) << "------------- iteration " << iter++;
      quiescent = true;
      std::map<peerid::PeerID, std::vector<SendableRaftMessage>> send;
      for (auto i = group_.begin(); i != group_.end(); ++i) {
        send[i->first] = i->second->SendableMessages();
      }
      for (auto i = send.begin(); i != send.end(); ++i) {
        for (auto msg : i->second) {
          quiescent = false;
          std::set<peerid::PeerID> send_to;
          if (msg.to().has_value()) {
            send_to.insert(*msg.to());
          } else if (group_.count(i->first)) {
            send_to = group_[i->first]->peers();
          } else {
            LOG(INFO) << "dropping targetted send to nonexistent peer " << i->first;
            continue;
          }
          for (auto peer : send_to) {
            if (group_.count(peer) == 0) {
              LOG(INFO) << "dropping broadcast send to nonexistent peer " << peer;
              continue;
            }
            LOG(VERBOSE) << "  >>> send from " << i->first << " to " << peer;
            LOG(VERBOSE) << "  ::: " << MsgStr(msg.message());
            group_[peer]->Receive(&ctx, msg.message(), i->first);
            LOG(VERBOSE) << "  <<< send complete";
          }
        }
      }
    }
  }

  void CommitOnAll(const enclaveconfig::RaftConfig& config) {
    bool quiescent = false;
    std::map<peerid::PeerID, LogIdx> committed;
    LOG(INFO) << "Waiting for commits to quiesce on all replicas";
    for (auto i = group_.begin(); i != group_.end(); ++i) {
      committed[i->first] = i->second->commit_idx();
      LOG(INFO) << "  initial on " << i->first << " : " << i->second->commit_idx();
    }
    RouteMessages();
    while (!quiescent) {
      LOG(INFO) << "TICK";
      quiescent = true;
      for (int i = 0; i < config.heartbeat_ticks(); i++) {
        for (auto i = group_.begin(); i != group_.end(); ++i) {
          i->second->TimerTick(&ctx);
        }
        RouteMessages();
      }
      for (auto i = group_.begin(); i != group_.end(); ++i) {
        if (committed[i->first] != i->second->commit_idx()) {
          quiescent = false;
          committed[i->first] = i->second->commit_idx();
          LOG(INFO) << "  update on " << i->first << " : " << i->second->commit_idx();
        }
      }
    }
    LOG(INFO) << "Commits quiesced";
  }

  peerid::PeerID ElectLeader(const enclaveconfig::RaftConfig& config) {
    LOG(INFO) << "Electing leader";
    std::set<peerid::PeerID> leaders;
    while (leaders.size() == 0) {
      RouteMessages();
      for (int i = 0; i < config.election_ticks() * 3; i++) {
        for (auto i = group_.begin(); i != group_.end(); ++i) {
          if (i->second->is_leader()) { leaders.insert(i->first); }
        }
        if (leaders.size()) break;
        LOG(INFO) << "Tick: " << i;
        for (auto i = group_.begin(); i != group_.end(); ++i) {
          i->second->TimerTick(&ctx);
        }
        RouteMessages();
      }
    }
    CHECK(leaders.size() == 1);
    LOG(INFO) << "Elected leader: " << leaders.begin()->DebugString();
    return *leaders.begin();
  }

  std::map<peerid::PeerID, std::unique_ptr<Raft>> group_;
  context::Context ctx;
};

TEST_F(RaftTest, CommitOnAll) {
  auto config = DefaultConfig();
  SetUpRaft(3, config);
  // Get a leader
  peerid::PeerID leader = ElectLeader(config);
  LOG(INFO) "============== SENDING LOG TO LEADER " << leader;
  auto [loc, err] = group_[leader]->ClientRequest(&ctx, "abc");
  ASSERT_EQ(error::OK, err);
  EXPECT_GE(loc.term(), 1);  // may have been a few terms to elect leader
  EXPECT_GE(loc.idx(), 1);  // leader election adds entry to log
  CommitOnAll(config);
  for (auto i = group_.begin(); i != group_.end(); ++i) {
    std::string last_log;
    LOG(INFO) << "replica logs for " << i->first;
    while(true) {
      auto [idx, e] = i->second->TakeCommittedLog();
      if (idx == 0) break;
      last_log = e.data();
      LOG(INFO) << "\tidx: " << idx << " : " << last_log;
      if (last_log == "abc") {
        EXPECT_EQ(idx, loc.idx());
        EXPECT_EQ(e.term(), loc.term());
      }
    }
    ASSERT_EQ(last_log, "abc");
  }
}

TEST_F(RaftTest, CommitIfOneDown) {
  auto config = DefaultConfig();
  SetUpRaft(3, config);
  // Remove one of the participants.
  group_.erase(group_.begin());
  peerid::PeerID leader = ElectLeader(config);
  LOG(INFO) "============== SENDING LOG TO LEADER " << leader;
  auto [loc, err] = group_[leader]->ClientRequest(&ctx, "abc");
  ASSERT_EQ(error::OK, err);
  EXPECT_GE(loc.term(), 1);  // may have been a few terms to elect leader
  EXPECT_GE(loc.idx(), 1);  // leader election adds entry to log
  CommitOnAll(config);
  for (auto i = group_.begin(); i != group_.end(); ++i) {
    std::string last_log;
    LOG(INFO) << "replica logs for " << i->first;
    while(true) {
      auto [idx, e] = i->second->TakeCommittedLog();
      if (idx == 0) break;
      last_log = e.data();
      LOG(INFO) << "\tidx: " << idx << " : " << last_log;
      if (last_log == "abc") {
        EXPECT_EQ(idx, loc.idx());
        EXPECT_EQ(e.term(), loc.term());
      }
    }
    ASSERT_EQ(last_log, "abc");
  }
}

TEST_F(RaftTest, SingleReplicaGroup) {
  auto config = DefaultConfig();
  SetUpRaft(1, DefaultConfig());
  peerid::PeerID leader = ElectLeader(config);
  LOG(INFO) "============== SENDING LOG TO LEADER " << leader;
  auto [loc, err] = group_[leader]->ClientRequest(&ctx, "abc");
  ASSERT_EQ(error::OK, err);
  EXPECT_GE(loc.term(), 1);  // may have been a few terms to elect leader
  EXPECT_GE(loc.idx(), 1);  // leader election adds entry to log
  CommitOnAll(config);
  for (auto i = group_.begin(); i != group_.end(); ++i) {
    std::string last_log;
    LOG(INFO) << "replica logs for " << i->first;
    while(true) {
      auto [idx, e] = i->second->TakeCommittedLog();
      if (idx == 0) break;
      last_log = e.data();
      LOG(INFO) << "\tidx: " << idx << " : " << last_log;
      if (last_log == "abc") {
        EXPECT_EQ(idx, loc.idx());
        EXPECT_EQ(e.term(), loc.term());
      }
    }
    ASSERT_EQ(last_log, "abc");
  }
}

TEST_F(RaftTest, QuorumSize) {
  EXPECT_EQ(Raft::quorum_size(3, 0), 2);
  EXPECT_EQ(Raft::quorum_size(4, 0), 3);
  EXPECT_EQ(Raft::quorum_size(2, 0), 2);
  EXPECT_EQ(Raft::quorum_size(3, 1), 3);
  EXPECT_EQ(Raft::quorum_size(4, 1), 3);
}

TEST_F(RaftTest, RelinquishLeadership) {
  auto config = DefaultConfig();
  SetUpRaft(2, DefaultConfig());
  auto leader = ElectLeader(config);
  LOG(INFO) << "==================== LEADER " << leader << " calling RelinquishLeadership";
  group_[leader]->RelinquishLeadership(&ctx);
  RouteMessages();
  EXPECT_FALSE(group_[leader]->is_leader());
  peerid::PeerID expected_new_leader;
  for (auto iter = group_.begin(); iter != group_.end(); ++iter) {
    if (iter->first == leader) { continue; }
    expected_new_leader = iter->first;
  }
  EXPECT_TRUE(expected_new_leader.Valid());
  EXPECT_TRUE(group_[expected_new_leader]->is_leader());
}

}  // namespace svr2::raft
