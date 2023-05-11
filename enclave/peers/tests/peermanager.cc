// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP context
//TESTDEP noise
//TESTDEP noise-c
//TESTDEP noisewrap
//TESTDEP peerid
//TESTDEP sip
//TESTDEP sender
//TESTDEP env
//TESTDEP env/test
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "peers/peers.h"
#include "env/env.h"
#include "env/test/test.h"
#include "util/log.h"
#include "proto/e2e.pb.h"
#include <memory>
#include <iostream>

namespace svr2::peers {

#define ATTESTATION_TIMEOUT 3600

class PeerManagerTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  e2e::Attestation attestation;
  context::Context ctx;

  PeerMessage* FromEnclaveMessage(const EnclaveMessage& msg, const peerid::PeerID& from) {
    auto out = ctx.Protobuf<PeerMessage>();
    out->MergeFrom(msg.peer_message());
    from.ToString(out->mutable_peer_id());
    return out;
  }

  void SetUp() {
    mgr1 = std::make_unique<PeerManager>();
    mgr2 = std::make_unique<PeerManager>();
    ASSERT_EQ(error::OK, mgr1->Init(&ctx));
    ASSERT_EQ(error::OK, mgr2->Init(&ctx));
    mgr1->SetPeerAttestationTimestamp(&ctx, now, ATTESTATION_TIMEOUT);
    mgr2->SetPeerAttestationTimestamp(&ctx, now, ATTESTATION_TIMEOUT);
    env::test::SentMessages();  // clear sent messages from previous tests
  }

  EnclaveMessage Sent() {
    auto msgs = env::test::SentMessages();
    CHECK(msgs.size() == 1);
    return std::move(msgs[0]);
  }

  void Connect1To2() {
    e2e::EnclaveToEnclaveMessage* e2e;
    ASSERT_EQ(error::OK, mgr1->ConnectToPeer(&ctx, mgr2->ID()));
    EnclaveMessage em = Sent();
    ASSERT_EQ(em.inner_case(), EnclaveMessage::kPeerMessage);
    ASSERT_EQ(error::OK, mgr2->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr1->ID()), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_TRUE(e2e->connected());
    em = Sent();
    ASSERT_EQ(error::OK, mgr1->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr2->ID()), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_TRUE(e2e->connected());
  }

  google::protobuf::Arena arena;
  std::unique_ptr<PeerManager> mgr1;
  std::unique_ptr<PeerManager> mgr2;
  util::UnixSecs now = 1000;
};

TEST_F(PeerManagerTest, SuccessfulCommunicationAcrossManagers) {
  Connect1To2();
  e2e::EnclaveToEnclaveMessage* e2e;
  e2e::EnclaveToEnclaveMessage send;
  send.mutable_raft_message()->set_term(123);
  ASSERT_EQ(error::OK, mgr1->SendToPeer(&ctx, mgr2->ID(), send));
  EnclaveMessage em = Sent();
  ASSERT_EQ(error::OK, mgr2->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr1->ID()), &e2e));
  ASSERT_NE(e2e, nullptr);
  ASSERT_EQ(e2e->raft_message().term(), 123);
}

TEST_F(PeerManagerTest, SendConnected) {
  Connect1To2();
  e2e::EnclaveToEnclaveMessage send;
  send.set_connected(true);
  ASSERT_EQ(error::Peers_SendConnect, mgr1->SendToPeer(&ctx, mgr2->ID(), send));
}

TEST_F(PeerManagerTest, AcceptUnparsable) {
  PeerMessage msg;
  msg.set_syn("this is not parsable protobuf serialized data");
  mgr1->ID().ToString(msg.mutable_peer_id());
  e2e::EnclaveToEnclaveMessage* e2e;
  ASSERT_EQ(error::Peers_AcceptParseHandshake, mgr2->RecvFromPeer(&ctx, msg, &e2e));
  ASSERT_EQ(PEER_DISCONNECTED, mgr2->PeerState(&ctx, mgr1->ID()));
}

TEST_F(PeerManagerTest, RecvConnectToConnected) {
  ASSERT_EQ(error::OK, mgr2->ConnectToPeer(&ctx, mgr1->ID()));
  Sent();
  Connect1To2();
}

TEST_F(PeerManagerTest, FinishConnectUnparsable) {
  PeerMessage msg;
  msg.set_synack("this is not parsable protobuf serialized data");
  mgr1->ID().ToString(msg.mutable_peer_id());
  e2e::EnclaveToEnclaveMessage* e2e;
  ASSERT_EQ(error::OK, mgr2->ConnectToPeer(&ctx, mgr1->ID()));
  ASSERT_EQ(error::Peers_FinishParseHandshake, mgr2->RecvFromPeer(&ctx, msg, &e2e));
  ASSERT_EQ(PEER_DISCONNECTED, mgr2->PeerState(&ctx, mgr1->ID()));
}

TEST_F(PeerManagerTest, ConnectToConnected) {
  Connect1To2();
  Connect1To2();
}

TEST_F(PeerManagerTest, ReInit) {
  ASSERT_EQ(error::Peers_ReInit, mgr1->Init(&ctx));
}

TEST_F(PeerManagerTest, NoInit) {
  mgr1 = std::make_unique<PeerManager>();
  e2e::EnclaveToEnclaveMessage* e2e;
  ASSERT_EQ(error::Peers_NoInit, mgr1->ConnectToPeer(&ctx, mgr2->ID()));
  PeerMessage msg;
  ASSERT_EQ(error::Peers_NoInit, mgr1->RecvFromPeer(&ctx, msg, &e2e));
  e2e::EnclaveToEnclaveMessage send;
  ASSERT_EQ(error::Peers_NoInit, mgr1->SendToPeer(&ctx, mgr2->ID(), send));
  ASSERT_FALSE(mgr1->ID().Valid());
}

TEST_F(PeerManagerTest, PeerState) {
  e2e::EnclaveToEnclaveMessage* e2e;
  ASSERT_EQ(PEER_DISCONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  ASSERT_EQ(error::OK, mgr1->ConnectToPeer(&ctx, mgr2->ID()));
  ASSERT_EQ(PEER_CONNECTING, mgr1->PeerState(&ctx, mgr2->ID()));
  EnclaveMessage em = Sent();
  ASSERT_EQ(em.inner_case(), EnclaveMessage::kPeerMessage);
  ASSERT_EQ(PEER_DISCONNECTED, mgr2->PeerState(&ctx, mgr1->ID()));
  ASSERT_EQ(error::OK, mgr2->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr1->ID()), &e2e));
  ASSERT_NE(e2e, nullptr);
  ASSERT_TRUE(e2e->connected());
  ASSERT_EQ(PEER_CONNECTED, mgr2->PeerState(&ctx, mgr1->ID()));
  em = Sent();
  ASSERT_EQ(error::OK, mgr1->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr2->ID()), &e2e));
  ASSERT_NE(e2e, nullptr);
  ASSERT_TRUE(e2e->connected());
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
}

TEST_F(PeerManagerTest, TimeoutAttestation) {
  Connect1To2();
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  mgr1->SetPeerAttestationTimestamp(&ctx, now, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  // Go up to but not over threshold.
  mgr1->SetPeerAttestationTimestamp(&ctx, now + ATTESTATION_TIMEOUT, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  // Actually go over threshold.
  mgr1->SetPeerAttestationTimestamp(&ctx, now + ATTESTATION_TIMEOUT + 1, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_DISCONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  // Confirm that RST was sent.
  EnclaveMessage em = Sent();
  ASSERT_EQ(em.peer_message().inner_case(), PeerMessage::kRst);
  ASSERT_EQ(em.peer_message().peer_id(), mgr2->ID().AsString());
}

TEST_F(PeerManagerTest, AttestationRefreshStallsTimeout) {
  Connect1To2();
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  mgr1->SetPeerAttestationTimestamp(&ctx, now, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  // Go up to but not over threshold.
  mgr1->SetPeerAttestationTimestamp(&ctx, now + ATTESTATION_TIMEOUT, ATTESTATION_TIMEOUT);
  mgr2->SetPeerAttestationTimestamp(&ctx, now + ATTESTATION_TIMEOUT, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
  ASSERT_EQ(PEER_CONNECTED, mgr2->PeerState(&ctx, mgr1->ID()));
  
  ASSERT_EQ(error::OK, mgr2->RefreshAttestation(&ctx));
  EnclaveMessage em = Sent();

  e2e::EnclaveToEnclaveMessage* e2e;
  ASSERT_EQ(error::OK, mgr1->RecvFromPeer(&ctx, *FromEnclaveMessage(em, mgr2->ID()), &e2e));
  ASSERT_TRUE(e2e == nullptr);

  mgr1->SetPeerAttestationTimestamp(&ctx, now + ATTESTATION_TIMEOUT + ATTESTATION_TIMEOUT, ATTESTATION_TIMEOUT);
  ASSERT_EQ(PEER_CONNECTED, mgr1->PeerState(&ctx, mgr2->ID()));
}

}  // namespace svr2::peers
