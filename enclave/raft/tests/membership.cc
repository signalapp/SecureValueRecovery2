// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP peerid
//TESTDEP context
//TESTDEP sip
//TESTDEP sender
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include <set>
#include "peerid/peerid.h"
#include "raft/membership.h"
#include "env/env.h"
#include "util/log.h"

namespace svr2::raft {

class MembershipTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init();
  }

  error::Error ValidProgression(const ReplicaGroup& g1, const ReplicaGroup& g2, const std::string& leader, size_t supermajority) {
    auto [m1, err1] = Membership::FromProto(g1);
    auto [m2, err2] = Membership::FromProto(g2);
    CHECK(err1 == error::OK && err2 == error::OK);
    peerid::PeerID leader_peer;
    CHECK(error::OK == leader_peer.FromString(leader));
    auto err = Membership::ValidProgressionForLeader(leader_peer, *m1, *m2, supermajority);
    LOG(INFO) << "ValidProgressionForLeader: " << err;
    return err;
  }
};

TEST_F(MembershipTest, FromProtoBadPeer) {
  ReplicaGroup g;
  g.add_replicas()->set_peer_id("invalid");
  auto [out, err] = Membership::FromProto(g);
  EXPECT_EQ(out.get(), nullptr);
  EXPECT_EQ(err, error::Peers_InvalidID);
}

TEST_F(MembershipTest, FromProtoDuplicatePeer) {
  ReplicaGroup g;
  g.add_replicas()->set_peer_id("12345678901234567890123456789012");
  g.add_replicas()->set_peer_id("12345678901234567890123456789012");
  auto [out, err] = Membership::FromProto(g);
  EXPECT_EQ(out.get(), nullptr);
  EXPECT_EQ(err, error::Membership_DuplicateReplicaInReplicaGroup);
}

TEST_F(MembershipTest, FromProtoSuccess) {
  ReplicaGroup g;
  g.add_replicas()->set_peer_id("REPLICA........................0");
  g.add_replicas()->set_peer_id("REPLICA........................1");
  g.add_replicas()->set_peer_id("REPLICA........................2");
  g.add_replicas()->set_peer_id("REPLICA........................3");
  g.mutable_replicas(1)->set_voting(true);
  g.mutable_replicas(2)->set_voting(true);
  auto [out, err] = Membership::FromProto(g);
  EXPECT_NE(out.get(), nullptr);
  EXPECT_EQ(err, error::OK);
  EXPECT_EQ(4, out->all_replicas().size());
  EXPECT_EQ(2, out->voting_replicas().size());
  EXPECT_EQ(1, out->voting_replicas().count(peerid::PeerID(reinterpret_cast<const uint8_t*>("REPLICA........................1"))));
  EXPECT_EQ(1, out->voting_replicas().count(peerid::PeerID(reinterpret_cast<const uint8_t*>("REPLICA........................2"))));
}

TEST_F(MembershipTest, ValidProgressionForLeader) {
  ReplicaGroup g1;
  g1.add_replicas()->set_peer_id("12345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("22345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("32345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("42345678901234567890123456789012");
  g1.mutable_replicas(0)->set_voting(true);
  g1.mutable_replicas(1)->set_voting(true);
  g1.mutable_replicas(2)->set_voting(true);

  auto leader = g1.replicas(0).peer_id();

  ReplicaGroup g2 = g1;
  EXPECT_EQ(error::Membership_NoMembershipChanges, ValidProgression(g1, g2, leader, 0));

  g2 = g1;
  g2.mutable_replicas(0)->set_voting(false);
  EXPECT_EQ(error::Membership_LeaderRemovedFromVoting, ValidProgression(g1, g2, leader, 0));

  g2 = g1;
  g2.mutable_replicas(1)->set_voting(false);
  g2.mutable_replicas(2)->set_voting(false);
  EXPECT_EQ(error::Membership_TooManyMembershipChanges, ValidProgression(g1, g2, leader, 0));

  g2 = g1;
  g2.mutable_replicas()->erase(g2.mutable_replicas()->begin());
  EXPECT_EQ(error::Membership_LeaderRemovedFromVoting, ValidProgression(g1, g2, leader, 0));

  // Delete a voting (non-leader) replica entirely.
  g2 = g1;
  g2.mutable_replicas()->erase(++g2.mutable_replicas()->begin());
  EXPECT_EQ(error::OK, ValidProgression(g1, g2, leader, 0));
}

TEST_F(MembershipTest, MembershipCannotShrinkToOrBelowSupermajority) {
  ReplicaGroup g1;
  g1.add_replicas()->set_peer_id("12345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("22345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("32345678901234567890123456789012");
  g1.add_replicas()->set_peer_id("42345678901234567890123456789012");
  g1.mutable_replicas(0)->set_voting(true);
  g1.mutable_replicas(1)->set_voting(true);
  g1.mutable_replicas(2)->set_voting(true);

  auto leader = g1.replicas(0).peer_id();

  ReplicaGroup g2 = g1;
  g2.mutable_replicas(1)->set_voting(false);
  EXPECT_EQ(error::Membership_SuperMajorityLost, ValidProgression(g1, g2, leader, 2));
  g2.mutable_replicas(2)->set_voting(false);
  EXPECT_EQ(error::Membership_SuperMajorityLost, ValidProgression(g1, g2, leader, 2));
}

}  // namespace svr2::raft
