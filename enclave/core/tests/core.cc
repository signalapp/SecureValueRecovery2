// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP core/coretest
//TESTDEP core
//TESTDEP groupclock
//TESTDEP timeout
//TESTDEP client
//TESTDEP db
//TESTDEP merkle
//TESTDEP raft
//TESTDEP peers
//TESTDEP peerid
//TESTDEP sender
//TESTDEP util
//TESTDEP context
//TESTDEP hmac
//TESTDEP sha
//TESTDEP minimums
//TESTDEP noise
//TESTDEP noise-c
//TESTDEP noisewrap
//TESTDEP env
//TESTDEP env/test
//TESTDEP sip
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium
//TESTDEP ristretto

#include <vector>
#include <deque>
#include <algorithm>
#include <memory>
#include <iostream>

#include <gtest/gtest.h>
#include <noise/protocol/errors.h>

#include "core/core.h"
#include "env/env.h"
#include "util/log.h"
#include "proto/enclaveconfig.pb.h"
#include "proto/e2e.pb.h"
#include "proto/client3.pb.h"
#include "proto/client4.pb.h"
#include "noise/noise.h"
#include "env/test/test.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "db/db3.h"
#include "metrics/metrics.h"
#include "core/coretest/testingcore.h"
#include "core/coretest/replicagroup.h"
#include "core/coretest/testingclient.h"
#include "ristretto/ristretto.h"

// This test is pretty large and contains a lot of code which should maybe be
// moved into some coretest library at a later date.  There's a few very
// important functions in the CoreTest fixture:
//
//   - PassMessages - pass a series of messages between multiple cores
//   - ClientRequest - issue a client request and get back a response
//
// Both PassMessages and ClientRequest rely on a "CoreSet" of a group of cores
// that can pass messages to each other, and a "first" core, a core to which
// a starting message has just been sent and which should have put a first
// set of messages into env::test::SentMessages.
//
// Tests are then built on top of these functions.

#define NOISE_OK(x) do { \
  int out = (x); \
  if (out != NOISE_ERROR_NONE) { \
    char buf[64]; \
    noise_strerror(out, buf, sizeof(buf)); \
    ASSERT_EQ(out, NOISE_ERROR_NONE) << "Noise error: " << buf; \
  } \
} while (0)

namespace svr2::core {
using svr2::core::test::TestingCore;
using svr2::core::test::ReplicaGroup;
using svr2::core::test::TestingClient;

// Valid scalar and point to create valid create requests:
const std::string valid_ristretto_scalar(
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 32);
// point = base * valid_ristretto_scalar
const std::string valid_ristretto_point(
    "\x44\xc2\x09\x97\xf9\x50\xa4\x18\x23\xb3\xf5\xf4\x61\x89\xa6\x0d\x39\x42\xff\x8c\x1a\xe3\x8d\x64\xb6\x67\x99\x3a\xe4\x95\x4b\x07", 32);

namespace {
struct ReplicaGroupConfig {
  enclaveconfig::EnclaveConfig ecfg;
  uint32_t min_voting;
  uint32_t max_voting;
  size_t initial_voting;
  size_t initial_nonvoting;
  size_t initial_nonmember;

  enclaveconfig::InitConfig init_config() const {
    enclaveconfig::InitConfig cfg;
    cfg.mutable_enclave_config()->MergeFrom(ecfg);
    cfg.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR2);
    cfg.mutable_group_config()->set_min_voting_replicas(min_voting);
    cfg.mutable_group_config()->set_max_voting_replicas(max_voting);
    cfg.mutable_group_config()->set_attestation_timeout(3600);
    return cfg;
  }
};

enum class CoreRole {
  Leader,
  VotingNonLeader,
  NonVoting
};
};

class CoreTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  HostToEnclaveResponse Response(std::vector<EnclaveMessage> msgs) {
    CHECK(msgs.size() == 1);
    CHECK(msgs[0].inner_case() == EnclaveMessage::kH2EResponse);
    return std::move(*msgs[0].mutable_h2e_response());
  }

  std::vector<EnclaveMessage> SentMessages() {
    return env::test::SentMessages();
  }

  void SetUp() {
    ctx = &ctx_;
    // clear sent messages.
    SentMessages();
    valid_enclave_config.Clear();
    auto raft_config = valid_enclave_config.mutable_raft();
    raft_config->set_election_ticks(4);
    raft_config->set_heartbeat_ticks(2);
    raft_config->set_replication_chunk_bytes(1<<20);
    raft_config->set_replica_voting_timeout_ticks(16);
    raft_config->set_replica_membership_timeout_ticks(32);
    raft_config->set_log_max_bytes(1<<20);
    raft_config->set_batch_messages_if_backlog_reaches(0);
    valid_enclave_config.set_e2e_txn_timeout_ticks(30);
    valid_enclave_config.set_send_timestamp_ticks(10);
    client_request = 10000;
    valid_init_config.Clear();
    valid_init_config.mutable_enclave_config()->CopyFrom(valid_enclave_config);
    valid_init_config.set_initial_timestamp_unix_secs(1);
    valid_init_config.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR2);
    valid_init_config.mutable_group_config()->set_min_voting_replicas(1);
    valid_init_config.mutable_group_config()->set_max_voting_replicas(5);
    valid_init_config.mutable_group_config()->set_attestation_timeout(3600);
    valid_init_config.mutable_group_config()->set_simulated(true);
    env::test::ResetRandomNumberGenerator();
  }

  typedef std::map<peerid::PeerID, Core*> CoreMap;
  typedef std::map<peerid::PeerID, std::vector<EnclaveMessage>> PassMessagesOut;

  // Passes back and forth all PeerMessage messages, and returns all non-PeerMessage
  // messages, until there are no more messages to pass.  The messages in SentMessages
  // are considered to be from [first].
  PassMessagesOut PassMessages(const CoreMap& cores, Core* first, bool drop_offline=true) {
    PassMessagesOut out;
    bool quiescent = false;
    std::map<peerid::PeerID, std::deque<EnclaveMessage>> to_send;
    auto first_msgs = env::test::SentMessages();
    LOG(INFO) << "### starting message passing from " << first->ID() << " with " << first_msgs.size() << " messages";
    std::move(std::begin(first_msgs), std::end(first_msgs), std::back_inserter(to_send[first->ID()]));
    while (to_send.size()) {
      auto i = to_send.begin();
      const peerid::PeerID& from = i->first;
      std::deque<EnclaveMessage>* msgs = &i->second;
      if (msgs->size() == 0) {
        to_send.erase(from);
        continue;
      }
      EnclaveMessage msg = std::move(msgs->front());
      msgs->pop_front();
      if (msg.inner_case() != EnclaveMessage::kPeerMessage) {
        LOG(INFO) << "# non-peer message from " << from;
        out[from].push_back(std::move(msg));
        continue;
      }
      UntrustedMessage req;
      *req.mutable_peer_message() = std::move(*msg.mutable_peer_message());
      peerid::PeerID to;
      to.FromString(req.peer_message().peer_id());
      from.ToString(req.mutable_peer_message()->mutable_peer_id());
      context::Context ctx;
      auto find = cores.find(to);
      if (find == cores.end()) {
        LOG(INFO) << "# offline recipient " << to;
        if (!drop_offline) {
          out[from].push_back(std::move(msg));
        }
        continue;
      }
      LOG(INFO) << "#####################################################";
      LOG(INFO) << "# peer message to " << to << " from " << from;
      find->second->Receive(&ctx, req);
      auto out_msgs = env::test::SentMessages();
      LOG(INFO) << "# yielded " << out_msgs.size();
      std::move(std::begin(out_msgs), std::end(out_msgs), std::back_inserter(to_send[to]));
    }
    LOG(INFO) << "### message passing complete";
    return out;
  }

  uint64_t client_request;

  void ClientRequest(const CoreMap& cores, Core* core, const google::protobuf::MessageLite& req, google::protobuf::MessageLite* cli_resp, const std::string auth_id, bool drop_offline=true) {
    // Set up client handshake.
    NoiseHandshakeState* hsp;
    NOISE_OK(noise_handshakestate_new_by_id(&hsp, &client::client_protocol, NOISE_ROLE_INITIATOR));
    noise::HandshakeState hs = noise::WrapHandshakeState(hsp);

    uint64_t client_id = 0;
    {  // Create new client
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(++client_request);
      auto newc = host->mutable_new_client();
      newc->set_client_authenticated_id(auth_id);
      context::Context ctx;
      ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
      auto out = PassMessages(cores, core, drop_offline);
      ASSERT_EQ(out[core->ID()].size(), 1);
      auto resp = out[core->ID()][0].h2e_response();
      ASSERT_EQ(resp.request_id(), client_request);
      client_id = resp.new_client_reply().client_id();
      ASSERT_GT(client_id, 0);

      auto hs_msg = resp.new_client_reply().handshake_start();
      NOISE_OK(noise_dhstate_set_public_key(
          noise_handshakestate_get_remote_public_key_dh(hsp),
          noise::StrU8Ptr(hs_msg.test_only_pubkey()),
          hs_msg.test_only_pubkey().size()));
    }
    NOISE_OK(noise_handshakestate_start(hsp));
    ASSERT_EQ(NOISE_ACTION_WRITE_MESSAGE, noise_handshakestate_get_action(hsp));

    NoiseCipherState* txp;
    NoiseCipherState* rxp;
    {  // Finish client handshake
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(++client_request);
      auto ec = host->mutable_existing_client();
      ec->mutable_data()->resize(noise::HANDSHAKE_INIT_SIZE, '\0');
      NoiseBuffer write_buf = noise::BufferOutputFromString(ec->mutable_data());
      NOISE_OK(noise_handshakestate_write_message(hsp, &write_buf, nullptr));
      ec->mutable_data()->resize(write_buf.size, '\0');
      ec->set_client_id(client_id);
      context::Context ctx;
      ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
      auto out = PassMessages(cores, core, drop_offline);
      ASSERT_EQ(out[core->ID()].size(), 1);
      auto resp = out[core->ID()][0].h2e_response();
      ASSERT_EQ(resp.request_id(), client_request);
      ASSERT_EQ(NOISE_ACTION_READ_MESSAGE, noise_handshakestate_get_action(hsp));
      ASSERT_EQ(resp.status(), error::OK);
      ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kExistingClientReply);
      auto crep = resp.mutable_existing_client_reply();
      NoiseBuffer read_buf = noise::BufferInputFromString(crep->mutable_data());
      NOISE_OK(noise_handshakestate_read_message(hsp, &read_buf, nullptr));
      ASSERT_EQ(NOISE_ACTION_SPLIT, noise_handshakestate_get_action(hsp));
      NOISE_OK(noise_handshakestate_split(hsp, &txp, &rxp));
    }
    noise::CipherState tx = noise::WrapCipherState(txp);
    noise::CipherState rx = noise::WrapCipherState(rxp);
    {  // send the request, parse response.
      std::string req_str;
      ASSERT_TRUE(req.SerializeToString(&req_str));
      auto [ciphertext, encrypt_err] = noise::Encrypt(txp, req_str);
      ASSERT_EQ(error::OK, encrypt_err);
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(++client_request);
      auto ec = host->mutable_existing_client();
      ec->set_client_id(client_id);
      ec->set_data(ciphertext);
      context::Context ctx;
      ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
      auto out = PassMessages(cores, core, drop_offline);
      ASSERT_EQ(out[core->ID()].size(), 1);
      auto resp = out[core->ID()][0].h2e_response();
      ASSERT_EQ(resp.request_id(), client_request);
      ASSERT_EQ(resp.status(), error::OK);
      ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kExistingClientReply);
      auto ec2 = resp.existing_client_reply();
      auto [plaintext, decrypt_err] = noise::Decrypt(rxp, ec2.data());
      ASSERT_EQ(error::OK, decrypt_err);
      ASSERT_TRUE(cli_resp->ParseFromString(plaintext));
    }
  }

  UntrustedMessage PeerMessage(const peerid::PeerID& from, const peerid::PeerID& to, EnclaveMessage msg) {
    CHECK(msg.inner_case() == EnclaveMessage::kPeerMessage);
    if (msg.peer_message().peer_id() != to.AsString()) {
      peerid::PeerID id;
      CHECK(error::OK == id.FromString(msg.peer_message().peer_id()));
      LOG(ERROR) << "unexpected peer ID: " << id;
      CHECK(false);
    }
    UntrustedMessage req;
    *req.mutable_peer_message() = std::move(*msg.mutable_peer_message());
    from.ToString(req.mutable_peer_message()->mutable_peer_id());
    return req;
  }

  enclaveconfig::EnclaveConfig valid_enclave_config;
  enclaveconfig::InitConfig valid_init_config;
  context::Context ctx_;
  context::Context* ctx;
};

static void BackupRestoreTest(ReplicaGroupConfig cfg, CoreRole connect_to, bool drop_leader, std::map<size_t, test::PartitionID>& partition) {
  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);

  // tik tok
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  auto [pin, e1] = util::StringToByteArray<32>("PIN45678901234567890123456789012");
  auto [secret, e2] = util::StringToByteArray<48>("SECRET78901234567890123456789012");
  ASSERT_TRUE(e1 == error::OK && e2 == error::OK);

  size_t core_num = 0;
  switch(connect_to) {
    case CoreRole::Leader:
      core_num = 0;
      break;
    case CoreRole::VotingNonLeader:
      ASSERT_TRUE(cfg.initial_voting > 1);
      core_num = 1;
      break;
    case CoreRole::NonVoting:
      ASSERT_TRUE(cfg.initial_nonvoting > 1);
      core_num = cfg.initial_voting;
      break;
  }

  auto client_core = replica_group.get_core(core_num);

  // Block 1: Client requests backup
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestBackup(secret, pin, 10);
    replica_group.TickTock(false);

    auto backup_response = cl.get_backup_response();
    ASSERT_NE(backup_response, nullptr);
    LOG(INFO) << "created backup";
    ASSERT_EQ(backup_response->status(), client::BackupResponse::OK);
  }
  {
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestTries();
    replica_group.TickTock(false);
    auto tries_response = cl.get_tries_response();
    ASSERT_NE(tries_response, nullptr);
    ASSERT_EQ(tries_response->status(), client::TriesResponse::OK);
    ASSERT_EQ(tries_response->tries(), 10);
    ASSERT_EQ(tries_response->exposed(), false);
  }
  {
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestExpose(secret);
    replica_group.TickTock(false);
    auto expose_response = cl.get_expose_response();
    ASSERT_NE(expose_response, nullptr);
    LOG(INFO) << "backup expose";
    ASSERT_EQ(expose_response->status(), client::ExposeResponse::OK);
  }
  {
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestTries();
    replica_group.TickTock(false);
    auto tries_response = cl.get_tries_response();
    ASSERT_NE(tries_response, nullptr);
    ASSERT_EQ(tries_response->status(), client::TriesResponse::OK);
    ASSERT_EQ(tries_response->tries(), 10);
    ASSERT_EQ(tries_response->exposed(), true);
  }

  // Now introduce problems if requested
  if(drop_leader) {
    auto leader = replica_group.get_core(replica_group.GroupLeaderIndex());
    leader->Pause(false);
  }
  replica_group.CreatePartition(partition);

  // run long enough to elect a new leader
  for(size_t i = 0; i < 100*cfg.ecfg.raft().election_ticks(); ++i) {
    replica_group.TickTock(false);
  }

  // Block 2: Client requests restore
  {
    auto [main_partition, partition_size] = test::LargestPartition(partition);
    switch(connect_to) {
      case CoreRole::Leader:
        core_num = replica_group.GroupLeaderIndex();
        break;
      case CoreRole::VotingNonLeader: {
        // Can't capture main_partition until C++20, need to assign it
        auto maybe_it = std::find_if(partition.begin(), partition.end(),
                    [mp = main_partition, &replica_group, cfg](auto it) {
                        auto c = replica_group.get_core(it.first);
                        return it.second == mp
                                    && !c->leader()
                                    && c->voting();});
        // Make sure you put some voting members in the big partition or this
        // will fail
        ASSERT_NE(maybe_it, partition.end());
        core_num = maybe_it->first;
        break;
        }
      case CoreRole::NonVoting: {
        auto maybe_it = std::find_if(partition.begin(), partition.end(),
                    [mp = main_partition, &replica_group, cfg](auto it) {
                        auto c = replica_group.get_core(it.first);
                        return it.second == mp
                                    && !c->voting()
                                    && c->serving();});
        // Make sure you put some non-voting members in the big partition or
        // this will fail!
        ASSERT_NE(maybe_it, partition.end());
        core_num = maybe_it->first;
        break;
        }
    }

    client_core = replica_group.get_core(core_num);
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    LOG(INFO) << "About to restore with core " << core_num << " (CoreRole: " << (int)connect_to << ")";
    cl.RequestRestore(pin);
    replica_group.TickTock(false);

    auto restore_response = cl.get_restore_response();
    ASSERT_NE(restore_response, nullptr);
    LOG(INFO) << "Super Secret: " << restore_response->data();
    ASSERT_EQ(util::ByteArrayToString(secret), restore_response->data());
  }
}

static void WrongPINTest(ReplicaGroupConfig cfg, CoreRole connect_to, bool drop_leader, std::map<size_t, test::PartitionID>& partition) {

  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);

  // tik tok
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  auto [pin, e1] = util::StringToByteArray<32>("PIN45678901234567890123456789012");
  auto [wrong_pin, e2] = util::StringToByteArray<32>("SIN45678901234567890123456789012");
  auto [secret, e3] = util::StringToByteArray<48>("SECRET78901234567890123456789012");
  ASSERT_TRUE(e1 == error::OK && e2 == error::OK && e3 == error::OK);
  size_t num_tries = 3;

  size_t core_num = 0;
  switch(connect_to) {
    case CoreRole::Leader:
      core_num = 0;
      break;
    case CoreRole::VotingNonLeader:
      ASSERT_TRUE(cfg.initial_voting > 1);
      core_num = 1;
      break;
    case CoreRole::NonVoting:
      ASSERT_TRUE(cfg.initial_nonvoting > 1);
      core_num = cfg.initial_voting;
      break;
  }

  auto client_core = replica_group.get_core(core_num);

  // Block 1: Client requests backup
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestBackup(secret, pin, num_tries);
    replica_group.TickTock(false);

    auto backup_response = cl.get_backup_response();
    ASSERT_NE(backup_response, nullptr);
    LOG(INFO) << "created backup";
  }
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestExpose(secret);
    replica_group.TickTock(false);

    auto expose_response = cl.get_expose_response();
    ASSERT_NE(expose_response, nullptr);
    LOG(INFO) << "created backup";
  }

  // Now introduce problems if requested
  if(drop_leader) {
    auto leader = replica_group.get_core(replica_group.GroupLeaderIndex());
    leader->Pause(false);
  }
  replica_group.CreatePartition(partition);

  // run long enough to elect a new leader
  for(size_t i = 0; i < 4*cfg.ecfg.raft().election_ticks(); ++i) {
    replica_group.TickTock(false);
  }

  // Block 2: Client requests restore with wrong pin
  {

    auto [main_partition, partition_size] = test::LargestPartition(partition);
    switch(connect_to) {
      case CoreRole::Leader:
        core_num = replica_group.GroupLeaderIndex();
        break;
      case CoreRole::VotingNonLeader: {
        // Can't capture main_partition until C++20, need to assign it
        auto maybe_it = std::find_if(partition.begin(), partition.end(),
                    [mp = main_partition, &replica_group, cfg](auto it) {
                        auto c = replica_group.get_core(it.first);
                        return it.second == mp
                                    && !c->leader()
                                    && c->voting();});
        // Make sure you put some voting members in the big partition or this
        // will fail
        ASSERT_NE(maybe_it, partition.end());
        core_num = maybe_it->first;
        break;
        }
      case CoreRole::NonVoting: {
        auto maybe_it = std::find_if(partition.begin(), partition.end(),
                    [mp = main_partition, &replica_group, cfg](auto it) {
                        auto c = replica_group.get_core(it.first);
                        return it.second == mp
                                    && !c->voting()
                                    && c->serving();});
        // Make sure you put some non-voting members in the big partition or
        // this will fail!
        ASSERT_NE(maybe_it, partition.end());
        core_num = maybe_it->first;
        break;
        }
    }

    client_core = replica_group.get_core(core_num);
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    for(size_t i = 0; i < num_tries; ++i) {
      cl.RequestRestore(wrong_pin);
      replica_group.TickTock(false);

      auto restore_response = cl.get_restore_response();
      ASSERT_NE(restore_response, nullptr);
      LOG(INFO) << "tries remaining: " << restore_response->tries() << " data: " << restore_response->data();
      ASSERT_NE(util::ByteArrayToString(secret), restore_response->data());
    }

    // now try correct PIN and confirm it is gone
    cl.RequestRestore(pin);
    replica_group.TickTock(false);

    auto restore_response = cl.get_restore_response();
    ASSERT_NE(restore_response, nullptr);
    LOG(INFO) << "correct PIN tries remaining: " << restore_response->tries() << " data: " << restore_response->data();
    ASSERT_NE(util::ByteArrayToString(secret), restore_response->data());
  }
}

void ConfirmWillNotServeClientRequests(ReplicaGroup& replica_group) {
  auto leader = replica_group.get_leader_core();
  auto [pin, e1] = util::StringToByteArray<32>("PIN45678901234567890123456789012");
  auto [wrong_pin, e2] = util::StringToByteArray<32>("SIN45678901234567890123456789012");
  auto [secret, e3] = util::StringToByteArray<48>("SECRET78901234567890123456789012");
  ASSERT_TRUE(e1 == error::OK && e2 == error::OK && e3 == error::OK);
  size_t num_tries = 3;

  //Client requests backup
  TestingClient cl(*leader, "authenticated_id");

  cl.RequestHandshake();
  // start the handshake
  ASSERT_EQ(error::OK, leader->ProcessAllIncomingMessages());
  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());
  //finish the handshake
  ASSERT_EQ(error::OK, leader->ProcessAllIncomingMessages());
  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());

  cl.RequestBackup(secret, pin, num_tries);
  ASSERT_EQ(error::OK, leader->ProcessAllIncomingMessages());

  auto h2e_msgs = leader->take_host_to_enclave_responses();
  auto& h2e_response = h2e_msgs[0];
  ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
  ASSERT_EQ(h2e_response.status(), error::Core_NotEnoughVotingReplicas);
}

void SelfHealingTest(ReplicaGroupConfig cfg) {
  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);

  size_t initial_members = cfg.initial_nonvoting + cfg.initial_voting;
  ASSERT_EQ(replica_group.num_voting(), 1);

  for(size_t i = 0; i < initial_members; ++i) {
    if (replica_group.num_voting() < cfg.min_voting) {
      ConfirmWillNotServeClientRequests(replica_group);
    }

    replica_group.TickTock(false);
    ASSERT_EQ(replica_group.num_voting(), std::min(2+i, initial_members));
  }
  size_t num_voting = replica_group.num_voting();

  // remove two voting non-leader
  LOG(INFO) << "Removing two non-leader voting members";
  auto leader_core = replica_group.get_leader_core();
  TestingCore* non_leader_core = replica_group.get_voting_nonleader_core();
  if(non_leader_core != nullptr) {
    LOG(INFO) << "STOPPING peer " << non_leader_core->ID()
      << "(leader: " << leader_core->ID() << ")";
    non_leader_core->Pause(false);
  }
  non_leader_core = replica_group.get_voting_nonleader_core();
  if(non_leader_core != nullptr) {
    LOG(INFO) << "STOPPING peer " << non_leader_core->ID()
      << "(leader: " << leader_core->ID() << ")";
    non_leader_core->Pause(false);
  }

  // even though we stopped them the replica group counts them as voting
  ASSERT_EQ(replica_group.num_voting(), num_voting);

  // replica_membership_timeout_ticks is time to kick out a member
  // replica_voting_timeout_ticks is time to demote from voting
  // tick until it is demoted
  auto voting_timeout_ticks = cfg.ecfg.raft().replica_voting_timeout_ticks();
  for(size_t i = 0; i < voting_timeout_ticks; ++i) {
    LOG(INFO) << "\nTICK " << i << "\n";
    replica_group.TickTock(false);
  }
  LOG(INFO) << "NUM_VOTING before demotion: " << num_voting << " after demotion: "
    << replica_group.num_voting();
  ASSERT_EQ(replica_group.num_voting(), num_voting - 1);

  // Tick again and eliminate the second core
  replica_group.TickTock(false);
  LOG(INFO) << "NUM_VOTING before demotion: " << num_voting << " after demotion: "
    << replica_group.num_voting();
  ASSERT_EQ(replica_group.num_voting(), num_voting - 2);
}

TEST_F(CoreTest, SelfHealingGrowthTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 5,
    .max_voting = 9,
    .initial_voting = 1,
    .initial_nonvoting = 7,
    .initial_nonmember = 2
  };
  SelfHealingTest(cfg);
}

TEST_F(CoreTest, CreateReplicaGroup) {
  ReplicaGroup replica_group{};
  ReplicaGroupConfig cfg{
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
  };
  replica_group.Init(cfg.init_config(), 5, 3, 2);

  // tik tok
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  ASSERT_TRUE(replica_group.get_core(0)->leader());
  ASSERT_TRUE(replica_group.get_core(0)->serving());
  for(size_t i = 1; i < 8; ++i) {
    ASSERT_FALSE(replica_group.get_core(i)->leader());
    ASSERT_TRUE(replica_group.get_core(i)->serving());
  }

  ASSERT_FALSE(replica_group.get_core(8)->leader());
  ASSERT_FALSE(replica_group.get_core(8)->serving());
  ASSERT_FALSE(replica_group.get_core(9)->leader());
  ASSERT_FALSE(replica_group.get_core(9)->serving());

  replica_group.TickTock(false);
  LOG(INFO) << "\nREMOVING LEADER\n" << " current leader: " << replica_group.GroupLeaderIndex() << "\n";

  // Now take out the leader
  replica_group.get_core(0)->Pause(false);
  // tik tok until election should have happened
  for(size_t i = 0; i < 4*valid_enclave_config.raft().election_ticks(); ++i) {
    replica_group.TickTock(false);
  }
  ASSERT_TRUE(
    replica_group.get_core(1)->leader() ||
    replica_group.get_core(2)->leader() ||
    replica_group.get_core(3)->leader() ||
    replica_group.get_core(4)->leader());

  LOG(INFO) << "\nNEW LEADER\n" << " current leader: " << replica_group.GroupLeaderIndex()
  << " (" << replica_group.GroupLeader() <<  ")\n";
}

TEST_F(CoreTest, TestPartition) {
  ReplicaGroup replica_group{};
  ReplicaGroupConfig cfg{
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
  };
  replica_group.Init(cfg.init_config(), 5, 3, 2);

  // tik tok
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  LOG(INFO) << "\nCREATE PARTITION\n" << " current leader: " << replica_group.GroupLeaderIndex() << "\n";
  replica_group.CreatePartition(std::map<size_t, test::PartitionID>{
    {0,1}, {1,1}, {5,1}, {6,1}, // has leader but only one other voting member
    {2,2}, {3,2}, {4,2}, {7,2}, {8,2}, {9,2}  // no leader, but quorum of voting members. Should take over
  });

  // tik tok until election should have happened and completed (it might go through more than one cycle)
  for(size_t i = 0; i < 4*valid_enclave_config.raft().election_ticks(); ++i) {
    replica_group.TickTock(false);
  }

  // add a voting member during the outage
  LOG(INFO) << "Core 8 Joining";
  auto peer3_id = replica_group.get_core(3)->ID();
  ASSERT_EQ(error::OK, replica_group.get_core(8)->JoinRaft(peer3_id));
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  LOG(INFO) << "Request voting for core " << replica_group.get_core(8)->ID();
  ASSERT_EQ(error::OK, replica_group.get_core(8)->RequestVoting());
  // ignore errors because raft joing might have failed if, e.g., the
  // load request was sent to a disconnected peer
  replica_group.TickTock(true);

  LOG(INFO) << "\nCLEAR PARTITION\n";
  replica_group.ClearPartition();
  replica_group.ForwardBlockedMessages();
  replica_group.TickTock(true);
  // replica_group.ClearBlockedMessages(); // This will drop all messages and leave replicas stuck in-flight until self-healing
  replica_group.PassMessagesUntilQuiet();

  // for(size_t i = 0; i < 2*valid_enclave_config.raft().election_ticks(); ++i) {
  //   replica_group.TickTock(false);
  // }

  LOG(INFO) << "\nNEW LEADER\n" << " current leader: " << replica_group.GroupLeaderIndex()
  << " (" << replica_group.GroupLeader() <<  ")\n";
  for(size_t i = 0; i < 10; ++i) {
    LOG(INFO) << "replica " << i << " (" << replica_group.get_core(i)->ID()
      << ") is_leader: " << replica_group.get_core(i)->leader()
      << ") serving: " << replica_group.get_core(i)->serving();
  }

  ASSERT_TRUE(
    replica_group.get_core(2)->leader() ||
    replica_group.get_core(3)->leader() ||
    replica_group.get_core(4)->leader());
}

TEST_F(CoreTest, BackupRestorePartitionNetworkTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, // has leader but only one other voting member
    {2,2}, {3,2}, {4,2}, {7,2}, {8,2}, {9,2}  // no leader, but quorum of voting members. Should take over
  };
  BackupRestoreTest(cfg, CoreRole::Leader, false, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, false, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, false, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  BackupRestoreTest(cfg, CoreRole::Leader, false, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, false, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, false, partition);
}

TEST_F(CoreTest, WrongPINPartitionNetworkTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, // has leader but only one other voting member
    {2,2}, {3,2}, {4,2}, {7,2}, {8,2}, {9,2}  // no leader, but quorum of voting members. Should take over
  };

  // TODO: Consider parameterized tests (http://google.github.io/googletest/reference/testing.html#TEST_P)
  WrongPINTest(cfg, CoreRole::Leader, false, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, false, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, false, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  WrongPINTest(cfg, CoreRole::Leader, false, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, false, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, false, partition);
}

TEST_F(CoreTest, BackupRestoreHealthyNetworkTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  // no partition in network
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, {9,1},
    {2,1}, {3,1}, {4,1}, {7,1}, {8,1}
  };
  BackupRestoreTest(cfg, CoreRole::Leader, false, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, false, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, false, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  BackupRestoreTest(cfg, CoreRole::Leader, false, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, false, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, false, partition);
}

TEST_F(CoreTest, WrongPINHealthyNetworkTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  // no partition in network
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, {9,1},
    {2,1}, {3,1}, {4,1}, {7,1}, {8,1}
  };
  WrongPINTest(cfg, CoreRole::Leader, false, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, false, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, false, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  WrongPINTest(cfg, CoreRole::Leader, false, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, false, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, false, partition);
}

TEST_F(CoreTest, BackupRestoreDropLeaderTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  // no partition in network
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, {9,1},
    {2,1}, {3,1}, {4,1}, {7,1}, {8,1}
  };
  BackupRestoreTest(cfg, CoreRole::Leader, true, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, true, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, true, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  BackupRestoreTest(cfg, CoreRole::Leader, true, partition);
  BackupRestoreTest(cfg, CoreRole::VotingNonLeader, true, partition);
  BackupRestoreTest(cfg, CoreRole::NonVoting, true, partition);
}

TEST_F(CoreTest, WrongPINDropLeaderTest) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 5,
    .initial_nonvoting = 3,
    .initial_nonmember = 2
  };
  // no partition in network
  std::map<size_t, test::PartitionID> partition = {
    {0,1}, {1,1}, {5,1}, {6,1}, {9,1},
    {2,1}, {3,1}, {4,1}, {7,1}, {8,1}
  };
  WrongPINTest(cfg, CoreRole::Leader, true, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, true, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, true, partition);
  cfg.ecfg.mutable_raft()->set_batch_messages_if_backlog_reaches(10);
  WrongPINTest(cfg, CoreRole::Leader, true, partition);
  WrongPINTest(cfg, CoreRole::VotingNonLeader, true, partition);
  WrongPINTest(cfg, CoreRole::NonVoting, true, partition);
}

TEST_F(CoreTest, EnclaveStatus) {
  ReplicaGroup replica_group{};
  ReplicaGroupConfig cfg{
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
  };
  replica_group.Init(cfg.init_config(), 5, 2, 0);

  // get status from leader and follower
  auto leader = replica_group.get_core(0);
  auto follower = replica_group.get_core(1);
  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());
  ASSERT_EQ(error::OK, follower->ProcessAllH2EResponses());
  leader->GetEnclaveStatus();
  follower->GetEnclaveStatus();

  replica_group.PassMessagesUntilQuiet();
  auto leader_status = leader->TakeExpectedEnclaveStatusReply();
  auto follower_status = follower->TakeExpectedEnclaveStatusReply();

  // drop the leader, have a new election, and try again
  leader->Pause(false);

  // run long enough to elect a new leader
  for(size_t i = 0; i < 4*valid_enclave_config.raft().election_ticks(); ++i) {
    replica_group.TickTock(false);
  }

  leader = replica_group.get_core(replica_group.GroupLeaderIndex());
  if(follower->leader()) {
    follower = replica_group.get_core(2);
  }

  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());
  ASSERT_EQ(error::OK, follower->ProcessAllH2EResponses());
  leader->GetEnclaveStatus();
  follower->GetEnclaveStatus();

  replica_group.PassMessagesUntilQuiet();
  leader_status = leader->TakeExpectedEnclaveStatusReply();
  follower_status = follower->TakeExpectedEnclaveStatusReply();
}

TEST_F(CoreTest, ClientRequests) {
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "sending backup request";

  client::Request req;
  auto b = req.mutable_backup();
  b->set_data("12345678901234567890123456789012");
  b->set_pin("12345678901234567890123456789012");
  b->set_max_tries(10);
  client::Response resp;
  ClientRequest(cores, core.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response::kBackup, resp.inner_case());
  ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());

  LOG(INFO) << "sending expose request";

  client::Request req2;
  auto a = req2.mutable_expose();
  a->set_data("12345678901234567890123456789012");
  client::Response resp2;
  ClientRequest(cores, core.get(), req2, &resp2, "backup7890123456");
  ASSERT_EQ(client::Response::kExpose, resp2.inner_case());
  ASSERT_EQ(client::ExposeResponse::OK, resp2.expose().status());

  LOG(INFO) << "sending restore request";

  client::Request req3;
  auto r = req3.mutable_restore();
  r->set_pin("12345678901234567890123456789012");
  client::Response resp3;
  ClientRequest(cores, core.get(), req3, &resp3, "backup7890123456");
  ASSERT_EQ(client::Response::kRestore, resp3.inner_case());
  ASSERT_EQ(client::RestoreResponse::OK, resp3.restore().status());
}

TEST_F(CoreTest, RestoreWithoutExpose) {
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "sending backup request";

  client::Request req;
  auto b = req.mutable_backup();
  b->set_data("12345678901234567890123456789012");
  b->set_pin("12345678901234567890123456789012");
  b->set_max_tries(10);
  client::Response resp;
  ClientRequest(cores, core.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response::kBackup, resp.inner_case());
  ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());

  LOG(INFO) << "sending restore request";

  client::Request req3;
  auto r = req3.mutable_restore();
  r->set_pin("12345678901234567890123456789012");
  client::Response resp3;
  ClientRequest(cores, core.get(), req3, &resp3, "backup7890123456");
  ASSERT_EQ(client::Response::kRestore, resp3.inner_case());
  ASSERT_EQ(client::RestoreResponse::MISSING, resp3.restore().status());
}

TEST_F(CoreTest, MultiNodeRaft) {
  auto [core1, err1] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err2, error::OK);
  auto [core3, err3] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err3, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID() << ", core3=" << core3->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();
  cores[core3->ID()] = core3.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core2 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1002);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest join on core 3";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1003);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1003);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core3 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1004);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1004);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  EXPECT_TRUE(core1->serving());
  EXPECT_TRUE(core1->leader());
  EXPECT_TRUE(core2->serving());
  EXPECT_FALSE(core2->leader());
  EXPECT_TRUE(core3->serving());
  EXPECT_FALSE(core3->leader());

  LOG(INFO) << "\n\nRequest to leader core1";
  client::Request req;
  auto b = req.mutable_backup();
  b->set_data("12345678901234567890123456789012");
  b->set_pin("12345678901234567890123456789012");
  b->set_max_tries(10);
  client::Response resp;
  ClientRequest(cores, core1.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response::kBackup, resp.inner_case());
  ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());

  LOG(INFO) << "\n\nElecting next leader";
  const int max_attempts = 100;
  cores.erase(core1->ID());  // core1 goes offline
  for (int i = 0; i < max_attempts && !core2->leader(); i++) {
    LOG(INFO) << "core2 tick";
    UntrustedMessage msg;
    msg.mutable_timer_tick()->set_new_timestamp_unix_secs(i);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    ASSERT_EQ(0, PassMessages(cores, core2.get()).size());
  }
  EXPECT_TRUE(core2->serving());
  EXPECT_TRUE(core2->leader());
  EXPECT_TRUE(core3->serving());
  EXPECT_FALSE(core3->leader());

  LOG(INFO) << "\n\nRequest to leader core2";

  client::Request req2;
  auto r = req2.mutable_expose();
  r->set_data("12345678901234567890123456789012");
  client::Response resp2;
  ClientRequest(cores, core2.get(), req2, &resp2, "backup7890123456");
  ASSERT_EQ(client::Response::kExpose, resp2.inner_case());
  ASSERT_EQ(client::ExposeResponse::OK, resp2.expose().status());

  LOG(INFO) << "\n\nRequest to non-leader core3";

  client::Request req3;
  auto r3 = req3.mutable_restore();
  r3->set_pin("12345678901234567890123456789012");
  client::Response resp3;
  ClientRequest(cores, core3.get(), req3, &resp3, "backup7890123456");
  ASSERT_EQ(client::Response::kRestore, resp3.inner_case());
  ASSERT_EQ(client::RestoreResponse::OK, resp3.restore().status());
}

TEST_F(CoreTest, RejectsUnsetHostTransactionID) {
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err, error::OK);
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  // host->set_request_id(1004);  // Not set, should error out.
  host->set_get_enclave_status(true);
  context::Context ctx;
  err = core->Receive(&ctx, msg);
  ASSERT_EQ(err, error::Core_HostToEnclaveTransactionID);
}

TEST_F(CoreTest, MultiJoinCausesDisconnectedPeersWhichThenConnect) {
  ReplicaGroup replica_group;
  auto enclave_config = valid_enclave_config;
  enclave_config.mutable_raft()->set_election_ticks(20);
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 2,
    .max_voting = 3,
  };
  replica_group.Init(
      cfg.init_config(),
      1,  // initial_voting
      0,  // initial_nonvoting
      2); // initial_nonmember
  // By issuing two relatively simultaneous JoinRaft connections, we
  // achieve a state where, during the raft Joining protocol, both cores
  // 1 and 2 create peer connections to core 0, but they do not establish
  // a peer connection to each other.
  LOG(INFO) << "Sending joins";
  replica_group.get_core(1)->JoinRaft(replica_group.get_core(0)->ID());
  replica_group.get_core(2)->JoinRaft(replica_group.get_core(0)->ID());
  LOG(INFO) << "Processing messages";
  ASSERT_EQ(error::OK, replica_group.PassMessagesUntilQuiet());
  LOG(INFO) << "Requesting voting";
  replica_group.get_core(1)->RequestVoting();
  ASSERT_EQ(error::OK, replica_group.PassMessagesUntilQuiet());
  replica_group.get_core(2)->RequestVoting();
  ASSERT_EQ(error::OK, replica_group.PassMessagesUntilQuiet());
  LOG(INFO) << "Partitioning";
  replica_group.CreatePartition(std::map<size_t, test::PartitionID>{
    {0,1},
    {1,2}, {2,2},
  });
  // What should happen now is that, as part of one of these ticks,
  // nodes 1 and 2 should detect that they're not connected to each
  // other and establish a connection.  In doing so, they make it possible
  // for themselves to run a leader election, and one of them should
  // be elected leader.
  for (int i = 0; i < valid_enclave_config.raft().election_ticks() * 10; i++) {
    LOG(INFO) << "Tick " << i;
    replica_group.TickTock(2, false);
  }
  EXPECT_TRUE(replica_group.get_core(1)->leader() || replica_group.get_core(2)->leader());
}

TEST_F(CoreTest, SetLogLevel) {
  auto old_log_level = ::svr2::util::log_level_to_write;
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err, error::OK);

  {
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(100);
    host->set_set_log_level(::svr2::enclaveconfig::LOG_LEVEL_MAX);
    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 100);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::Core_InvalidLogLevel);
  }
  {
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(101);
    host->set_set_log_level(::svr2::enclaveconfig::LOG_LEVEL_WARNING);
    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
    ASSERT_EQ(::svr2::util::log_level_to_write, ::svr2::enclaveconfig::LOG_LEVEL_WARNING);
    util::SetLogLevel(old_log_level);
    ASSERT_EQ(::svr2::util::log_level_to_write, old_log_level);
  }
}

TEST_F(CoreTest, ResetPeer){
  ReplicaGroup replica_group{};
  size_t initial_voting = 4;
  size_t initial_nonvoting = 0;
  size_t initial_nonmember = 0;
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 2,
    .max_voting = 3,
  };
  replica_group.Init(
      cfg.init_config(),
      initial_voting,
      initial_nonvoting,
      initial_nonmember);

  // get status from leader and follower
  auto leader = replica_group.get_core(0);
  auto follower = replica_group.get_core(1);
  ASSERT_EQ(error::OK, leader->ResetPeer(follower->ID()));
  replica_group.PassMessagesUntilQuiet();
  LOG(INFO) << "Reset peer";

  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());
  ASSERT_EQ(error::OK, follower->ProcessAllH2EResponses());
  leader->GetEnclaveStatus();
  follower->GetEnclaveStatus();

  replica_group.PassMessagesUntilQuiet();
  auto leader_status = leader->TakeExpectedEnclaveStatusReply();
  auto follower_status = follower->TakeExpectedEnclaveStatusReply();

  for(size_t i = 0; i < leader_status.peers_size(); ++i) {
    auto peer_status = leader_status.peers(i);
    peerid::PeerID pid;
    ASSERT_EQ(error::OK, pid.FromString(peer_status.peer_id()));
    if(pid == follower->ID()) {
      ASSERT_EQ(PEER_DISCONNECTED, peer_status.connection_status().state());
    }
  }

  replica_group.TickTock(false);
  replica_group.TickTock(false);

  ASSERT_EQ(error::OK, leader->ProcessAllH2EResponses());
  ASSERT_EQ(error::OK, follower->ProcessAllH2EResponses());
  leader->GetEnclaveStatus();
  follower->GetEnclaveStatus();

  replica_group.PassMessagesUntilQuiet();
  leader_status = leader->TakeExpectedEnclaveStatusReply();
  follower_status = follower->TakeExpectedEnclaveStatusReply();

  for(size_t i = 0; i < leader_status.peers_size(); ++i) {
    auto peer_status = leader_status.peers(i);
    peerid::PeerID pid;
    ASSERT_EQ(error::OK, pid.FromString(peer_status.peer_id()));
    if(pid == follower->ID()) {
      ASSERT_EQ(PEER_CONNECTED, peer_status.connection_status().state());
    }
  }
}

TEST_F(CoreTest, ReplicatingRowsWithMultiplePackets) {
  enclaveconfig::InitConfig config = valid_init_config;
  config.mutable_enclave_config()->mutable_raft()->set_replication_chunk_bytes(10 * 1024);  // holds ~17 logs
  auto [core1, err1] = Core::Create(ctx, config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, config);
  ASSERT_EQ(err2, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  for (uint64_t i = 0; i < 100; i++) {  // more logs than fit in replication_chunk_bytes
    LOG(INFO) << "\n\nRequest to leader core1";
    client::Request req;
    std::array<uint8_t, 16> backup_id = {0};
    util::BigEndian64Bytes(i, backup_id.data());

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);
    client::Response resp;
    ClientRequest(cores, core1.get(), req, &resp, util::ByteArrayToString(backup_id));
    ASSERT_EQ(client::Response::kBackup, resp.inner_case());
    ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core2 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1002);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  EXPECT_TRUE(core1->serving());
  EXPECT_TRUE(core1->leader());
  EXPECT_TRUE(core2->serving());
  EXPECT_FALSE(core2->leader());

  {
    LOG(INFO) << "\n\nRequest to core2";
    client::Request req;
    std::array<uint8_t, 16> backup_id = {0xff, 0xff, 0xff, 0xff};

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);
    client::Response resp;
    ClientRequest(cores, core2.get(), req, &resp, util::ByteArrayToString(backup_id));
    ASSERT_EQ(client::Response::kBackup, resp.inner_case());
    ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
  }
}

TEST_F(CoreTest, ReplicatingRowsWithTruncatedLog) {
  enclaveconfig::InitConfig config = valid_init_config;
  config.mutable_enclave_config()->mutable_raft()->set_log_max_bytes(10240);  // truncate log quickly
  auto [core1, err1] = Core::Create(ctx, config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, config);
  ASSERT_EQ(err2, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  for (uint64_t i = 0; i < 100; i++) {  // more logs than fit in replication_chunk_bytes
    LOG(INFO) << "\n\nRequest to leader core1";
    client::Request req;
    std::array<uint8_t, 16> backup_id = {0};
    util::BigEndian64Bytes(i, backup_id.data());

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);
    client::Response resp;
    ClientRequest(cores, core1.get(), req, &resp, util::ByteArrayToString(backup_id));
    ASSERT_EQ(client::Response::kBackup, resp.inner_case());
    ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core2 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1002);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  EXPECT_TRUE(core1->serving());
  EXPECT_TRUE(core1->leader());
  EXPECT_TRUE(core2->serving());
  EXPECT_FALSE(core2->leader());
}

TEST_F(CoreTest, RaftRemoval) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 2,
    .max_voting = 3,
    .initial_voting = 3,
    .initial_nonvoting = 0,
    .initial_nonmember = 0,
  };
  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);
  EXPECT_TRUE(replica_group.get_core(0)->leader());
  EXPECT_TRUE(replica_group.get_core(1)->active());
  EXPECT_TRUE(replica_group.get_core(1)->voting());

  LOG(INFO) << "================================== REMOVING " << replica_group.get_core(1)->ID();
  replica_group.get_core(1)->RaftRemoval();
  replica_group.PassMessagesUntilQuiet();
  EXPECT_TRUE(replica_group.get_core(0)->leader());
  EXPECT_EQ(0, replica_group.get_core(0)->all_replicas().count(replica_group.get_core(1)->ID()));
  EXPECT_EQ(0, replica_group.get_core(2)->all_replicas().count(replica_group.get_core(1)->ID()));
  // Keeping these tests in here for illustrative purposes:
  // Core 1 has been removed from Raft by this point, but it doesn't KNOW that it
  // has, because part of being removed is that it no longer receives Raft logs.
  EXPECT_TRUE(replica_group.get_core(1)->active());
  EXPECT_TRUE(replica_group.get_core(1)->voting());
}

TEST_F(CoreTest, RaftRemovalOfLeaderFails) {
  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 2,
    .max_voting = 3,
    .initial_voting = 3,
    .initial_nonvoting = 0,
    .initial_nonmember = 0,
  };
  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);
  EXPECT_TRUE(replica_group.get_core(0)->leader());
  EXPECT_TRUE(replica_group.get_core(1)->active());
  EXPECT_TRUE(replica_group.get_core(1)->voting());
  replica_group.get_core(0)->RaftRemoval();
  replica_group.PassMessagesUntilQuiet();
  EXPECT_TRUE(replica_group.get_core(0)->leader());
  EXPECT_EQ(1, replica_group.get_core(0)->all_replicas().count(replica_group.get_core(1)->ID()));
  EXPECT_EQ(error::Core_LeaderRemovingSelf, replica_group.ProcessAllH2EResponses());
}

TEST_F(CoreTest, Hashes2) {
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "sending backup request";

  client::Request req;
  auto b = req.mutable_backup();
  b->set_data("12345678901234567890123456789012");
  b->set_pin("12345678901234567890123456789012");
  b->set_max_tries(10);
  client::Response resp;
  ClientRequest(cores, core.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response::kBackup, resp.inner_case());
  ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());

  LOG(INFO) << "sending expose request";

  client::Request req2;
  auto a = req2.mutable_expose();
  a->set_data("12345678901234567890123456789012");
  client::Response resp2;
  ClientRequest(cores, core.get(), req2, &resp2, "backup7890123456");
  ASSERT_EQ(client::Response::kExpose, resp2.inner_case());
  ASSERT_EQ(client::ExposeResponse::OK, resp2.expose().status());

  LOG(INFO) << "sending restore request";

  client::Request req3;
  auto r = req3.mutable_restore();
  r->set_pin("12345678901234567890123456789012");
  client::Response resp3;
  ClientRequest(cores, core.get(), req3, &resp3, "backup7890123456");
  ASSERT_EQ(client::Response::kRestore, resp3.inner_case());
  ASSERT_EQ(client::RestoreResponse::OK, resp3.restore().status());

  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(10101);
    host->set_hashes(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 10101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kHashes);
    ASSERT_EQ(resp.status(), error::OK);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().db_hash().data())),
              3849877579579121162ULL);
    EXPECT_EQ(resp.hashes().commit_idx(), 4);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().commit_hash_chain().data())),
              17588214037507609329ULL);
  }
}

TEST_F(CoreTest, ReplicationRandom) {
  for (int test_i = 0; test_i < 10; test_i++) {
    enclaveconfig::InitConfig config = valid_init_config;
    config.mutable_enclave_config()->mutable_raft()->set_log_max_bytes(10240);
    auto [core1, err1] = Core::Create(ctx, config);
    ASSERT_EQ(err1, error::OK);
    auto [core2, err2] = Core::Create(ctx, config);
    ASSERT_EQ(err2, error::OK);
    LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID();

    // Create cores map for PassMessages
    CoreMap cores;
    cores[core1->ID()] = core1.get();
    cores[core2->ID()] = core2.get();

    {
      LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(1000);
      host->set_create_new_raft_group(true);

      context::Context ctx;
      ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
      auto out = env::test::SentMessages();
      ASSERT_EQ(1, out.size());
      auto resp = out[0].h2e_response();
      ASSERT_EQ(resp.request_id(), 1000);
      ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
      ASSERT_EQ(resp.status(), error::OK);
    }

    for (uint64_t i = 0; i < 100; i++) {  // more logs than fit in replication_chunk_bytes
      LOG(INFO) << "\n\nRequest to leader core1";
      client::Request req;
      std::array<uint8_t, 16> backup_id = {0};
      // Randomly order inserts
      util::BigEndian64Bytes(rand(), backup_id.data());

      auto b = req.mutable_backup();
      b->set_data("12345678901234567890123456789012");
      b->set_pin("12345678901234567890123456789012");
      b->set_max_tries(10);
      client::Response resp;
      ClientRequest(cores, core1.get(), req, &resp, util::ByteArrayToString(backup_id));
      ASSERT_EQ(client::Response::kBackup, resp.inner_case());
      ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
    }

    {
      LOG(INFO) << "\n\nRequest join on core 2";
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(1001);
      auto req = host->mutable_join_raft();
      core1->ID().ToString(req->mutable_peer_id());

      context::Context ctx;
      ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
      auto out = PassMessages(cores, core2.get());
      ASSERT_EQ(1, out[core2->ID()].size());
      auto resp = out[core2->ID()][0].h2e_response();
      ASSERT_EQ(resp.request_id(), 1001);
      ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
      ASSERT_EQ(resp.status(), error::OK);
    }

    {
      LOG(INFO) << "\n\nRequest hashes";
      UntrustedMessage msg;
      auto host = msg.mutable_h2e_request();
      host->set_request_id(1099);
      host->set_hashes(true);
      context::Context ctx;

      ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
      auto resp1 = Response(env::test::SentMessages());
      ASSERT_EQ(resp1.inner_case(), HostToEnclaveResponse::kHashes);
      ASSERT_EQ(resp1.status(), error::OK);

      ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
      auto resp2 = Response(env::test::SentMessages());
      ASSERT_EQ(resp2.inner_case(), HostToEnclaveResponse::kHashes);
      ASSERT_EQ(resp2.status(), error::OK);

      EXPECT_EQ(resp1.hashes().db_hash(), resp2.hashes().db_hash());
      EXPECT_EQ(resp1.hashes().commit_idx(), resp2.hashes().commit_idx());
      EXPECT_EQ(resp1.hashes().commit_hash_chain(), resp2.hashes().commit_hash_chain());
    }
  }
}

static e2e::ReplicateStatePush MakeReplicateStatePush(
    uint64_t repl_id,
    uint64_t seq,
    uint64_t first_log,
    size_t logs,
    bool db_to_end,
    size_t rows) {
  e2e::ReplicateStatePush p;
  p.set_replication_id(repl_id);
  p.set_replication_sequence(seq);
  p.set_first_log_idx(first_log);
  for (size_t i = 0; i < logs; i++) {
    p.add_entries();
  }
  p.set_db_to_end(db_to_end);
  for (size_t i = 0; i < rows; i++) {
    p.add_rows();
  }
  return p;
}

static void ReplicateStatePushMatches(const e2e::ReplicateStatePush& a, const e2e::ReplicateStatePush& b) {
  LOG(INFO) << "Testing replication ID " << a.replication_id() << "/" << b.replication_id() << " seq " << a.replication_sequence() << "/" << b.replication_sequence();
  EXPECT_EQ(a.replication_id(), b.replication_id());
  EXPECT_EQ(a.replication_sequence(), b.replication_sequence());
  EXPECT_EQ(a.first_log_idx(), b.first_log_idx());
  EXPECT_EQ(a.entries_size(), b.entries_size());
  EXPECT_EQ(a.db_to_end(), b.db_to_end());
  EXPECT_EQ(a.rows_size(), b.rows_size());
}

TEST_F(CoreTest, Replicator) {
  enclaveconfig::InitConfig cfg = valid_init_config;
  cfg.mutable_enclave_config()->mutable_raft()->set_replication_chunk_bytes(10240);
  cfg.mutable_enclave_config()->mutable_raft()->set_replication_pipeline(3);
  auto [core, err] = Core::Create(ctx, cfg);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();
  minimums::Minimums m;
  peers::PeerManager pm(&m);
  ASSERT_EQ(error::OK, pm.Init(ctx));

  LOG(INFO) << "\n\nCreating Raft group";
  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "\n\nAdding initial rows";
  for (uint8_t i = 0; i < 200; i++) {
    client::Request req;
    std::array<uint8_t, 16> backup_id = {i, 0};

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);
    client::Response resp;
    ClientRequest(cores, core.get(), req, &resp, util::ByteArrayToString(backup_id));
    ASSERT_EQ(client::Response::kBackup, resp.inner_case());
    ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
  }

  LOG(INFO) << "\n\nConnecting Core to PeerManager";
  {
    ASSERT_EQ(error::OK, pm.ConnectToPeer(ctx, core->ID()));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    ASSERT_EQ(2, msgs.size());  // synack + timestamp
    e2e::EnclaveToEnclaveMessage* e2e;
    ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[0]).peer_message(), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kConnected);
    ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[1]).peer_message(), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kTransactionRequest);
  }

  LOG(INFO) << "\n\nGetRaft";
  uint64_t group_id;
  uint64_t repl_id = 1;
  {
    e2e::EnclaveToEnclaveMessage msg;
    auto txn = msg.mutable_transaction_request();
    txn->set_request_id(1);
    txn->set_get_raft(true);
    ASSERT_EQ(error::OK, pm.SendToPeer(ctx, core->ID(), msg));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());  // synack + timestamp
    e2e::EnclaveToEnclaveMessage* e2e;
    ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[0]).peer_message(), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kTransactionResponse);
    ASSERT_EQ(e2e->transaction_response().inner_case(), e2e::TransactionResponse::kGetRaft);
    group_id = e2e->transaction_response().get_raft().group_config().group_id();
    ASSERT_NE(group_id, 0);
  }
  LOG(INFO) << "\n\nReplicateReq";
  std::string last_backup_id = "";
  std::deque<uint64_t> txns;
  {
    e2e::EnclaveToEnclaveMessage msg;
    auto txn = msg.mutable_transaction_request();
    txn->set_request_id(12345);
    txn->mutable_replicate_state()->set_group_id(group_id);
    txn->mutable_replicate_state()->set_replication_id(repl_id);
    ASSERT_EQ(error::OK, pm.SendToPeer(ctx, core->ID(), msg));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    std::vector<e2e::ReplicateStatePush> expected_pipeline = {
        MakeReplicateStatePush(repl_id, 0, 1, 79, false, 0),
        MakeReplicateStatePush(repl_id, 1, 80, 79, false, 0),
        MakeReplicateStatePush(repl_id, 2, 159, 43, false, 42),
    };
    ASSERT_EQ(expected_pipeline.size(), msgs.size());  // pipelining
    for (size_t i = 0; i < expected_pipeline.size(); i++) {
      e2e::EnclaveToEnclaveMessage* e2e;
      ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[i]).peer_message(), &e2e));
      ASSERT_NE(e2e, nullptr);
      ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kTransactionRequest);
      ASSERT_EQ(e2e->transaction_request().inner_case(), e2e::TransactionRequest::kReplicateStatePush);
      ReplicateStatePushMatches(
          e2e->transaction_request().replicate_state_push(),
          expected_pipeline[i]);
      txns.push_back(e2e->transaction_request().request_id());
      for (const auto& row : e2e->transaction_request().replicate_state_push().rows()) {
	e2e::DB2RowState rs;
	ASSERT_TRUE(rs.ParseFromString(row));
        ASSERT_LT(last_backup_id, rs.backup_id());
        last_backup_id = rs.backup_id();
      }
    }
  }
  LOG(INFO) << "\n\nAdding intermediate rows";
  for (uint8_t i = 0; i < 200; i++) {
    client::Request req;
    std::array<uint8_t, 16> backup_id = {i, 1};

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);
    client::Response resp;
    ClientRequest(cores, core.get(), req, &resp, util::ByteArrayToString(backup_id));
    ASSERT_EQ(client::Response::kBackup, resp.inner_case());
    ASSERT_EQ(client::BackupResponse::OK, resp.backup().status());
  }
  std::deque<e2e::ReplicateStatePush> expected_pushes = {
    MakeReplicateStatePush(repl_id, 3, 202, 79, false, 0),
    MakeReplicateStatePush(repl_id, 4, 281, 79, false, 0),
    MakeReplicateStatePush(repl_id, 5, 360, 42, false, 44),
    MakeReplicateStatePush(repl_id, 6, 402, 0, false, 97),
    MakeReplicateStatePush(repl_id, 7, 402, 0, false, 97),
    MakeReplicateStatePush(repl_id, 8, 402, 0, true, 79),
  };
  while (expected_pushes.size()) {
    e2e::EnclaveToEnclaveMessage msg;
    auto txn = msg.mutable_transaction_response();
    ASSERT_GT(txns.size(), 0);
    txn->set_request_id(txns.front());
    txns.pop_front();
    txn->set_status(error::OK);
    ASSERT_EQ(error::OK, pm.SendToPeer(ctx, core->ID(), msg));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    ASSERT_EQ(msgs.size(), 1);
    e2e::EnclaveToEnclaveMessage* e2e;
    ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[0]).peer_message(), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kTransactionRequest);
    ASSERT_EQ(e2e->transaction_request().inner_case(), e2e::TransactionRequest::kReplicateStatePush);
    ReplicateStatePushMatches(
        e2e->transaction_request().replicate_state_push(),
        expected_pushes.front());
    expected_pushes.pop_front();
    txns.push_back(e2e->transaction_request().request_id());
    for (const auto& row : e2e->transaction_request().replicate_state_push().rows()) {
      e2e::DB2RowState rs;
      ASSERT_TRUE(rs.ParseFromString(row));
      ASSERT_LT(last_backup_id, rs.backup_id());
      last_backup_id = rs.backup_id();
    }
  }
  while (txns.size() > 1) {
    e2e::EnclaveToEnclaveMessage msg;
    auto txn = msg.mutable_transaction_response();
    txn->set_request_id(txns.front());
    txns.pop_front();
    txn->set_status(error::OK);
    ASSERT_EQ(error::OK, pm.SendToPeer(ctx, core->ID(), msg));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    ASSERT_EQ(msgs.size(), 0);
  }
  {
    e2e::EnclaveToEnclaveMessage msg;
    auto txn = msg.mutable_transaction_response();
    ASSERT_EQ(txns.size(), 1);
    txn->set_request_id(txns.front());
    txns.pop_front();
    txn->set_status(error::OK);
    ASSERT_EQ(error::OK, pm.SendToPeer(ctx, core->ID(), msg));
    auto msgs = env::test::SentMessages();
    ASSERT_EQ(1, msgs.size());
    ASSERT_EQ(error::OK, core->Receive(ctx, PeerMessage(pm.ID(), core->ID(), msgs[0])));
    msgs = env::test::SentMessages();
    ASSERT_EQ(msgs.size(), 1);
    e2e::EnclaveToEnclaveMessage* e2e;
    ASSERT_EQ(error::OK, pm.RecvFromPeer(ctx, PeerMessage(core->ID(), pm.ID(), msgs[0]).peer_message(), &e2e));
    ASSERT_NE(e2e, nullptr);
    ASSERT_EQ(e2e->inner_case(), e2e::EnclaveToEnclaveMessage::kTransactionResponse);
    ASSERT_EQ(e2e->transaction_response().inner_case(), e2e::TransactionResponse::kStatus);
    ASSERT_EQ(e2e->transaction_response().status(), error::OK);
    ASSERT_EQ(e2e->transaction_response().request_id(), 12345);
  }
}


TEST_F(CoreTest, BackupResetsNumTries) {

  ReplicaGroupConfig cfg = {
    .ecfg = valid_enclave_config,
    .min_voting = 1,
    .max_voting = 1,
    .initial_voting = 3,
    .initial_nonvoting = 0,
    .initial_nonmember = 0
  };
  ReplicaGroup replica_group{};
  replica_group.Init(cfg.init_config(), cfg.initial_voting, cfg.initial_nonvoting, cfg.initial_nonmember);

  // tik tok
  replica_group.TickTock(false);
  replica_group.TickTock(false);

  auto [pin, e1] = util::StringToByteArray<32>("PIN45678901234567890123456789012");
  auto [wrong_pin, e2] = util::StringToByteArray<32>("SIN45678901234567890123456789012");
  auto [secret, e3] = util::StringToByteArray<48>("SECRET78901234567890123456789012");
  ASSERT_TRUE(e1 == error::OK && e2 == error::OK && e3 == error::OK);
  size_t num_tries = 3;

  size_t core_num = 0; // connect to the leader
  auto client_core = replica_group.get_core(core_num);

  // Client requests backup
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestBackup(secret, pin, num_tries);
    replica_group.TickTock(false);

    auto backup_response = cl.get_backup_response();
    ASSERT_NE(backup_response, nullptr);
    LOG(INFO) << "created backup";
  }

  // Client requests expose
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestExpose(secret);
    replica_group.TickTock(false);

    auto expose_response = cl.get_expose_response();
    ASSERT_NE(expose_response, nullptr);
    LOG(INFO) << "created expose";
  }

  // Client requests restore with wrong pin
  {
    client_core = replica_group.get_core(core_num);
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);
    cl.RequestRestore(wrong_pin);
    replica_group.TickTock(false);

    auto restore_response = cl.get_restore_response();
    ASSERT_NE(restore_response, nullptr);
    ASSERT_EQ(restore_response->tries(), num_tries - 1);
    ASSERT_NE(util::ByteArrayToString(secret), restore_response->data());

  }


  // Client requests backup again
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestBackup(secret, pin, num_tries);
    replica_group.TickTock(false);

    auto backup_response = cl.get_backup_response();
    ASSERT_NE(backup_response, nullptr);
    LOG(INFO) << "created backup";
  }

  // Client requests expose again
  {
    TestingClient cl(*client_core, "authenticated_id");

    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);

    cl.RequestExpose(secret);
    replica_group.TickTock(false);

    auto expose_response = cl.get_expose_response();
    ASSERT_NE(expose_response, nullptr);
    LOG(INFO) << "created expose";
  }

  // Client requests restore again and checks that the number of tries is correct
  {
    client_core = replica_group.get_core(core_num);
    TestingClient cl(*client_core, "authenticated_id");
    cl.RequestHandshake();
    replica_group.TickTock(false);
    replica_group.TickTock(false);
    cl.RequestRestore(pin);
    replica_group.TickTock(false);

    auto restore_response = cl.get_restore_response();
    ASSERT_NE(restore_response, nullptr);
    ASSERT_EQ(restore_response->tries(), num_tries);
    ASSERT_EQ(util::ByteArrayToString(secret), restore_response->data());

  }
}

TEST_F(CoreTest, MultiNodeRaftSVR3) {
  enclaveconfig::InitConfig config = valid_init_config;
  config.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR3);
  auto [core1, err1] = Core::Create(ctx, config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, config);
  ASSERT_EQ(err2, error::OK);
  auto [core3, err3] = Core::Create(ctx, config);
  ASSERT_EQ(err3, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID() << ", core3=" << core3->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();
  cores[core3->ID()] = core3.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core2 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1002);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest join on core 3";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1003);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1003);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  {
    LOG(INFO) << "\n\nRequest core3 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1004);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1004);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  EXPECT_TRUE(core1->serving());
  EXPECT_TRUE(core1->leader());
  EXPECT_TRUE(core2->serving());
  EXPECT_FALSE(core2->leader());
  EXPECT_TRUE(core3->serving());
  EXPECT_FALSE(core3->leader());

  LOG(INFO) << "\n\nRequest to leader core1";
  client::Request3 req;
  auto b = req.mutable_create();
  b->set_max_tries(10);
  b->mutable_blinded_element()->resize(db::DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(b->mutable_blinded_element()->data()));

  client::Response3 resp;
  ClientRequest(cores, core1.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response3::kCreate, resp.inner_case());
  ASSERT_EQ(client::CreateResponse::OK, resp.create().status());

  LOG(INFO) << "\n\nElecting next leader";
  const int max_attempts = 100;
  cores.erase(core1->ID());  // core1 goes offline
  for (int i = 0; i < max_attempts && !core2->leader(); i++) {
    LOG(INFO) << "core2 tick";
    UntrustedMessage msg;
    msg.mutable_timer_tick()->set_new_timestamp_unix_secs(i);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    PassMessages(cores, core2.get());
  }
  EXPECT_TRUE(core2->serving());
  EXPECT_TRUE(core2->leader());
  EXPECT_TRUE(core3->serving());
  EXPECT_FALSE(core3->leader());

  LOG(INFO) << "\n\nRequest to leader core2";

  client::Request3 req2;
  auto r = req2.mutable_evaluate();
  r->set_blinded_element(req.create().blinded_element());
  client::Response3 resp2;
  ClientRequest(cores, core2.get(), req2, &resp2, "backup7890123456");
  ASSERT_EQ(client::Response3::kEvaluate, resp2.inner_case());
  ASSERT_EQ(client::EvaluateResponse::OK, resp2.evaluate().status());
  ASSERT_EQ(resp.create().evaluated_element(), resp2.evaluate().evaluated_element());
}

TEST_F(CoreTest, Hashes3) {
  enclaveconfig::InitConfig config = valid_init_config;
  config.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR3);
  auto [core, err] = Core::Create(ctx, config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  std::string blinded;
  blinded.resize(db::DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded.data()));

  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "sending backup request";

  client::Request3 req;
  auto b = req.mutable_create();
  b->set_blinded_element(blinded);
  b->set_max_tries(10);
  client::Response3 resp;
  ClientRequest(cores, core.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response3::kCreate, resp.inner_case());
  ASSERT_EQ(client::CreateResponse::OK, resp.create().status());

  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(10101);
    host->set_hashes(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 10101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kHashes);
    ASSERT_EQ(resp.status(), error::OK);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().db_hash().data())),
              7514716392381643839ULL);
    EXPECT_EQ(resp.hashes().commit_idx(), 2);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().commit_hash_chain().data())),
              9155683825560991977ULL);
  }
}

TEST_F(CoreTest, RequestMetricsEnvStats) {
  auto [core, err] = Core::Create(ctx, valid_init_config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  metrics::ClearAllForTest();
  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(998);
    host->mutable_metrics()->set_update_env_stats(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 998);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kMetricsReply);
    ASSERT_GT(COUNTER(context, cpu_core_update_env_stats)->Value(), 0);
  }
  metrics::ClearAllForTest();
  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->mutable_metrics()->set_update_env_stats(false);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kMetricsReply);
    ASSERT_EQ(COUNTER(context, cpu_core_update_env_stats)->Value(), 0);
  }
}

TEST_F(CoreTest, AcceptsAndRejectsMinimums) {
  ReplicaGroup replica_group;
  replica_group.Init(valid_init_config, 3, 0, 0);
  auto leader = replica_group.get_leader_core();
  leader->take_host_to_enclave_responses();  // clear out any prior responses
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version-1);
    leader->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = leader->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::OK);
  }
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version-2);
    leader->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = leader->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::Minimums_LimitDecreased);
  }
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version+1);
    leader->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = leader->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::Minimums_ValueTooLow);
  }
  auto follower = replica_group.get_voting_nonleader_core();
  follower->take_host_to_enclave_responses();  // clear out any prior responses
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version);
    follower->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = follower->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::OK);
  }
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version-1);
    follower->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = follower->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::Minimums_LimitDecreased);
  }
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["minimums_test_version"] = minimums::Minimums::U64(env::test::minimums_test_version+1);
    follower->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = follower->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::Minimums_ValueTooLow);
  }
}

TEST_F(CoreTest, ReplicationReset) {
  auto [core1, err1] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err2, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  auto msgs = SentMessages();
  ASSERT_EQ(msgs.size(), 0);
  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    ASSERT_EQ(error::OK, core2->Receive(ctx, msg));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 1);
    auto resp = msgs[0];
    ASSERT_EQ(resp.inner_case(), EnclaveMessage::kPeerMessage);
    ASSERT_EQ(resp.peer_message().has_syn(), true);
  }
  {
    auto msg = PeerMessage(core2->ID(), core1->ID(), msgs[0]);
    ASSERT_EQ(error::OK, core1->Receive(ctx, msg));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 2);
    auto resp1 = msgs[0];
    ASSERT_EQ(resp1.peer_message().inner_case(), PeerMessage::kSynack);
    auto resp2 = msgs[1];  // timestamp transaction, ignorable
    ASSERT_EQ(resp2.peer_message().inner_case(), PeerMessage::kData);
  }
  {
    // synack
    auto msg1 = PeerMessage(core1->ID(), core2->ID(), msgs[0]);
    // timestamp request
    auto msg2 = PeerMessage(core1->ID(), core2->ID(), msgs[1]);
    ASSERT_EQ(error::OK, core2->Receive(ctx, msg1));
    ASSERT_EQ(error::OK, core2->Receive(ctx, msg2));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 3);
  }
  {
    // timestamp request
    auto msg1 = PeerMessage(core2->ID(), core1->ID(), msgs[0]);
    // raft request
    auto msg2 = PeerMessage(core2->ID(), core1->ID(), msgs[1]);
    // timestamp response
    auto msg3 = PeerMessage(core2->ID(), core1->ID(), msgs[2]);
    ASSERT_EQ(error::OK, core1->Receive(ctx, msg1));
    ASSERT_EQ(error::OK, core1->Receive(ctx, msg2));
    ASSERT_EQ(error::OK, core1->Receive(ctx, msg3));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 2);
  }
  {
    // timestamp response
    auto msg1 = PeerMessage(core1->ID(), core2->ID(), msgs[0]);
    // GetRaft
    auto msg2 = PeerMessage(core1->ID(), core2->ID(), msgs[1]);
    ASSERT_EQ(error::OK, core2->Receive(ctx, msg1));
    ASSERT_EQ(error::OK, core2->Receive(ctx, msg2));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 1);
  }
  {
    // GetRaft response
    auto msg1 = PeerMessage(core2->ID(), core1->ID(), msgs[0]);
    ASSERT_EQ(error::OK, core1->Receive(ctx, msg1));
    msgs = SentMessages();
    ASSERT_EQ(msgs.size(), 1);
    // msgs[0] now has our "please start replication" request
  }
  // We're now in a state where Core2 expects data from Core1.
  // We simulate Core1 crashing and the Core2 host noticing eventually
  // by passing a ResetPeer down to Core2.
  {
    LOG(INFO) << "\n\nReset core1 on core2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    core1->ID().ToString(host->mutable_reset_peer_id());

    ASSERT_EQ(error::OK, core2->Receive(ctx, msg));
    msgs = SentMessages();
    ASSERT_EQ(3, msgs.size());
    EXPECT_EQ(msgs[0].peer_message().inner_case(), PeerMessage::kRst);

    // This is the one we actually care about:  the ongoing
    // raft replication request is cancelled due to the ResetPeer call.
    EXPECT_EQ(msgs[1].h2e_response().request_id(), 1001);
    EXPECT_EQ(msgs[1].h2e_response().inner_case(), HostToEnclaveResponse::kStatus);
    EXPECT_EQ(msgs[1].h2e_response().status(), error::Core_E2ETransactionReset);

    // Our request to ResetPeer then succeeds.
    EXPECT_EQ(msgs[2].h2e_response().request_id(), 1002);
    EXPECT_EQ(msgs[2].h2e_response().inner_case(), HostToEnclaveResponse::kStatus);
    EXPECT_EQ(msgs[2].h2e_response().status(), error::OK);
  }
}

TEST_F(CoreTest, AcceptsMultiKeyMinimums) {
  ReplicaGroup replica_group;
  replica_group.Init(valid_init_config, 3, 0, 0);
  auto leader = replica_group.get_leader_core();
  leader->take_host_to_enclave_responses();  // clear out any prior responses
  {
    minimums::MinimumLimits lims;
    (*lims.mutable_lim())["a"] = minimums::Minimums::U64(1);
    (*lims.mutable_lim())["b"] = minimums::Minimums::U64(2);
    (*lims.mutable_lim())["c"] = minimums::Minimums::U64(3);
    (*lims.mutable_lim())["d"] = minimums::Minimums::U64(4);
    (*lims.mutable_lim())["e"] = minimums::Minimums::U64(5);
    (*lims.mutable_lim())["f"] = minimums::Minimums::U64(6);
    (*lims.mutable_lim())["g"] = minimums::Minimums::U64(7);
    (*lims.mutable_lim())["h"] = minimums::Minimums::U64(8);
    leader->UpdateMinimums(lims);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = leader->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::OK);
  }
}

TEST_F(CoreTest, HostDatabaseRequest) {
  ReplicaGroup replica_group;
  replica_group.Init(valid_init_config, 3, 0, 0);
  auto leader = replica_group.get_leader_core();
  leader->take_host_to_enclave_responses();  // clear out any prior responses
  {
    client::Request req;
    std::array<uint8_t, 16> backup_id = {1};

    auto b = req.mutable_backup();
    b->set_data("12345678901234567890123456789012");
    b->set_pin("12345678901234567890123456789012");
    b->set_max_tries(10);

    DatabaseRequest d;
    d.set_authenticated_id(util::ByteArrayToString(backup_id));
    req.SerializeToString(d.mutable_request());
    leader->DBRequest(d);
    replica_group.PassMessagesUntilQuiet();
    auto h2e_msgs = leader->take_host_to_enclave_responses();
    ASSERT_EQ(h2e_msgs.size(), 1);
    auto& h2e_response = h2e_msgs[0];
    ASSERT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(h2e_response.status(), error::OK);
  }
}

TEST_F(CoreTest, OldLeaderRelinquishesLeadershipWhenItCannotTalkToNewLeader) {
  ReplicaGroup replica_group;
  auto config = valid_init_config;
  auto raft = config.mutable_enclave_config()->mutable_raft();
  raft->set_election_ticks(10);
  raft->set_heartbeat_ticks(7);
  raft->set_replica_voting_timeout_ticks(100);
  raft->set_replica_membership_timeout_ticks(200);
  
  LOG(INFO) << "INIT";
  replica_group.Init(config, 3, 0, 0);
  auto leader1_idx = replica_group.GroupLeaderIndex();
  ASSERT_EQ(leader1_idx, 0);
  std::map<size_t, test::PartitionID> part = {
    {0, 3},
    {1, 4},
    {2, 4},
  };
  LOG(INFO) << "PARTITION - remove current leader from other replicas";
  replica_group.CreatePartition(part);
  LOG(INFO) << "ELECT LEADER - create a new leader";
  for (int i = 0; i < 20 && replica_group.GroupLeaderIndex() >= 3; i++) {
    replica_group.TickTock(4, true);
  }
  auto leader2_idx = replica_group.GroupLeaderIndex();
  ASSERT_LT(leader2_idx, 3);
  ASSERT_NE(leader1_idx, leader2_idx);
  auto leader2_core = replica_group.get_core(leader2_idx);
  LOG(INFO) << "LIMITS1 - create a few logs in the new leader, to get its logs ahead of the old one";
  minimums::MinimumLimits lim;
  (*lim.mutable_lim())["a"] = "b";
  leader2_core->UpdateMinimums(lim);
  leader2_core->UpdateMinimums(lim);
  leader2_core->UpdateMinimums(lim);
  leader2_core->UpdateMinimums(lim);
  replica_group.PassMessagesUntilQuiet();
  leader2_core->take_host_to_enclave_responses();

  LOG(INFO) << "DISCONNECT - since we drop some messages, reset all the peer connections to old leader";
  replica_group.ClearPartition();
  replica_group.get_core(0)->ResetPeer(replica_group.get_core(1)->ID());
  replica_group.get_core(0)->ResetPeer(replica_group.get_core(2)->ID());
  replica_group.get_core(1)->ResetPeer(replica_group.get_core(0)->ID());
  replica_group.get_core(2)->ResetPeer(replica_group.get_core(0)->ID());
  replica_group.PassMessagesUntilQuiet();
  LOG(INFO) << "RECONNECT - since we drop some messages, reset all the peer connections to old leader";
  replica_group.get_core(0)->ConnectPeer(replica_group.get_core(1)->ID());
  replica_group.get_core(0)->ConnectPeer(replica_group.get_core(2)->ID());
  replica_group.PassMessagesUntilQuiet();
  replica_group.ClearBlockedMessages();
  LOG(INFO) << "REPARTITION - put the old leader and the current follower together, away from the new leader";
  std::map<size_t, test::PartitionID> part2 = {
    {0, 3},
    {1, leader2_idx == 1 ? 4 : 3},
    {2, leader2_idx == 2 ? 4 : 3},
  };
  replica_group.CreatePartition(part2);
  LOG(INFO) << "LIMITS2 - have the old leader try to append a log entry";
  auto leader1_core = replica_group.get_core(leader1_idx);
  leader1_core->UpdateMinimums(lim);
  replica_group.PassMessagesUntilQuiet(3);
  LOG(INFO) << "CHECK - the old leader should learn that the term has increased from the follower, relinquishing leadership";
  ASSERT_FALSE(leader1_core->leader());
  LOG(INFO) << "REPARTITION - put the new leader and follower together, have some time pass";
  std::map<size_t, test::PartitionID> part3 = {
    {0, 3},
    {1, 4},
    {2, 4},
  };
  replica_group.CreatePartition(part3);
  LOG(INFO) << "LIMITS3 - write more logs, which should stop the old leader from becoming leader when it reconnects";
  leader2_core->UpdateMinimums(lim);
  leader2_core->UpdateMinimums(lim);
  replica_group.PassMessagesUntilQuiet();
  LOG(INFO) << "TIME PASSES - both partitions experience a few election cycles";
  for (int i = 0; i < 30; i++) {
    replica_group.TickTock(3, true);
    replica_group.TickTock(4, true);
  }
  LOG(INFO) << "PASS ALL - allow all messages to flow freely";
  replica_group.ClearPartition();
  replica_group.ForwardBlockedMessages();
  replica_group.PassMessagesUntilQuiet();
  ASSERT_FALSE(leader1_core->leader());
  LOG(INFO) << "LEADER ELECT - allow for a few election cycles to go by, since first may not elect a leader";
  for (int i = 0; i < 100 && replica_group.GroupLeaderIndex() >= 3; i++) {
    replica_group.TickAllTimers();
    replica_group.PassMessagesUntilQuiet();
  }
  ASSERT_LT(replica_group.GroupLeaderIndex(), 3);
  ASSERT_FALSE(leader1_core->leader());

  LOG(INFO) << "H2E_RESPONSE - get response from leader1_core->UpdateMinimums request";
  // It should have brought leader1_core up to date, and it should realize that its
  // log transaction has been canceled.
  auto h2e_msgs = leader1_core->take_host_to_enclave_responses();
  ASSERT_EQ(h2e_msgs.size(), 1);
  auto& h2e_response = h2e_msgs[0];
  ASSERT_EQ(h2e_msgs[0].status(), error::Core_LogTransactionCancelled);
}

TEST_F(CoreTest, Hashes4) {
  enclaveconfig::InitConfig config = valid_init_config;
  config.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR4);
  auto [core, err] = Core::Create(ctx, config);
  ASSERT_TRUE(core->ID().Valid());
  CoreMap cores;
  cores[core->ID()] = core.get();

  std::string blinded;
  blinded.resize(db::DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded.data()));

  {  // Set up as one-replica Raft
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(999);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 999);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  LOG(INFO) << "sending backup request";

  client::Request4 req;
  auto b = req.mutable_create();
  uint8_t enc[32] = {1};
  b->set_max_tries(10);
  b->set_oprf_secretshare(valid_ristretto_scalar);
  b->set_auth_commitment(valid_ristretto_point);
  b->set_encryption_secretshare(enc, 32);
  b->set_zero_secretshare(valid_ristretto_scalar);
  b->set_version(1);

  client::Response4 resp;
  ClientRequest(cores, core.get(), req, &resp, "backup7890123456");
  ASSERT_EQ(client::Response4::kCreate, resp.inner_case());
  ASSERT_EQ(client::Response4::OK, resp.create().status());

  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(10101);
    host->set_hashes(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 10101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kHashes);
    ASSERT_EQ(resp.status(), error::OK);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().db_hash().data())),
              14611402901957026671ULL);
    EXPECT_EQ(resp.hashes().commit_idx(), 2);
    EXPECT_EQ(util::BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(resp.hashes().commit_hash_chain().data())),
              11091854017836649273ULL);
  }
}

TEST_F(CoreTest, DB4NewNodeReplication) {
  auto config = valid_init_config;
  config.mutable_group_config()->set_db_version(enclaveconfig::DATABASE_VERSION_SVR4);
  config.mutable_group_config()->set_min_voting_replicas(1);
  config.mutable_group_config()->set_max_voting_replicas(3);
  config.mutable_enclave_config()->mutable_raft()->set_replication_chunk_bytes(10000);
  auto [core1, err1] = Core::Create(ctx, config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, config);
  ASSERT_EQ(err2, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  for (uint64_t i = 0; i < 100; i++) {
    LOG(INFO) << "\n\nRequest to leader core1";

    client::Request4 req;
    auto b = req.mutable_create();
    uint8_t enc[32] = {1};
    b->set_max_tries(10);
    b->set_oprf_secretshare(valid_ristretto_scalar);
    b->set_auth_commitment(valid_ristretto_point);
    b->set_encryption_secretshare(enc, 32);
    b->set_zero_secretshare(valid_ristretto_scalar);
    b->set_version(1);

    std::string auth_id = "XXXXXXXXbackup78";
    util::BigEndian64Bytes(i, reinterpret_cast<uint8_t*>(auth_id.data()));

    client::Response4 resp;
    ClientRequest(cores, core1.get(), req, &resp, auth_id);
    ASSERT_EQ(client::Response4::kCreate, resp.inner_case());
    ASSERT_EQ(client::Response4::OK, resp.create().status());
  }
  // Have one row be in an intermediate state.
  { uint64_t i = 0;
    LOG(INFO) << "\n\nRequest to leader core1";

    client::Request4 req;
    auto b = req.mutable_rotate_start();
    uint8_t enc[32] = {2};
    b->set_version(2);
    b->set_oprf_secretshare_delta(valid_ristretto_scalar);
    b->set_encryption_secretshare_delta(enc, 32);

    std::string auth_id = "XXXXXXXXbackup78";
    util::BigEndian64Bytes(i, reinterpret_cast<uint8_t*>(auth_id.data()));

    client::Response4 resp;
    ClientRequest(cores, core1.get(), req, &resp, auth_id);
    ASSERT_EQ(client::Response4::kRotateStart, resp.inner_case());
    ASSERT_EQ(client::Response4::OK, resp.rotate_start().status());
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);
  }

  HashResponse h1;
  HashResponse h2;
  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(10101);
    host->set_hashes(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 10101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kHashes);
    ASSERT_EQ(resp.status(), error::OK);
    h1 = resp.hashes();
  }
  {
    UntrustedMessage msg;

    auto host = msg.mutable_h2e_request();
    host->set_request_id(10101);
    host->set_hashes(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto resp = Response(env::test::SentMessages());
    ASSERT_EQ(resp.request_id(), 10101);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kHashes);
    ASSERT_EQ(resp.status(), error::OK);
    h2 = resp.hashes();
  }
  EXPECT_EQ(h1.db_hash(), h2.db_hash());
  EXPECT_EQ(h1.commit_hash_chain(), h2.commit_hash_chain());
  EXPECT_EQ(h1.commit_idx(), h2.commit_idx());
}

TEST_F(CoreTest, GroupTimeParticipants) {
  auto [core1, err1] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err1, error::OK);
  auto [core2, err2] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err2, error::OK);
  auto [core3, err3] = Core::Create(ctx, valid_init_config);
  ASSERT_EQ(err3, error::OK);
  LOG(INFO) << "core1=" << core1->ID() << ", core2=" << core2->ID() << ", core3=" << core3->ID();

  // Create cores map for PassMessages
  CoreMap cores;
  cores[core1->ID()] = core1.get();
  cores[core2->ID()] = core2.get();
  cores[core3->ID()] = core3.get();

  {
    LOG(INFO) << "\n\nSet up as one-replica Raft on core 1";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1000);
    host->set_create_new_raft_group(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = env::test::SentMessages();
    ASSERT_EQ(1, out.size());
    auto resp = out[0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1000);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    std::set<peerid::PeerID> want{};
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nRequest join on core 2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1001);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1001);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    std::set<peerid::PeerID> want{ core2->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nRequest core2 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1002);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core2->Receive(&ctx, msg));
    auto out = PassMessages(cores, core2.get());
    ASSERT_EQ(1, out[core2->ID()].size());
    auto resp = out[core2->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1002);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    std::set<peerid::PeerID> want{ core2->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nRequest join on core 3";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1003);
    auto req = host->mutable_join_raft();
    core1->ID().ToString(req->mutable_peer_id());

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1003);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    // core3 has joined but is not voting, use only core2.
    std::set<peerid::PeerID> want{ core2->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nDisconnect core2";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1004);
    host->set_reset_peer_id(core2->ID().AsString());

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = PassMessages(cores, core1.get());
    ASSERT_EQ(1, out[core1->ID()].size());
    auto resp = out[core1->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1004);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    // core1 has disconnected from core2, the only other voting member.
    // It should fall back to using all connected peers, which in this
    // case is core3.
    std::set<peerid::PeerID> want{ core3->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nDisconnect core3";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1005);
    host->set_reset_peer_id(core3->ID().AsString());

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = PassMessages(cores, core1.get());
    ASSERT_EQ(1, out[core1->ID()].size());
    auto resp = out[core1->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1005);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    // core1 has disconnected from all cores, it should just use
    // its own local time.
    std::set<peerid::PeerID> want{};
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nReconnect core3";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1006);
    host->set_connect_peer_id(core3->ID().AsString());

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = PassMessages(cores, core1.get());
    ASSERT_EQ(1, out[core1->ID()].size());
    auto resp = out[core1->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1006);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    // core1 has disconnected from all cores, it should just use
    // its own local time.
    std::set<peerid::PeerID> want{ core3->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nReconnect core2 (voting)";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1007);
    host->set_connect_peer_id(core2->ID().AsString());

    context::Context ctx;
    ASSERT_EQ(error::OK, core1->Receive(&ctx, msg));
    auto out = PassMessages(cores, core1.get());
    ASSERT_EQ(1, out[core1->ID()].size());
    auto resp = out[core1->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1007);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    // core1 has disconnected from all cores, it should just use
    // its own local time.
    std::set<peerid::PeerID> want{ core2->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

  {
    LOG(INFO) << "\n\nRequest core3 vote";
    UntrustedMessage msg;
    auto host = msg.mutable_h2e_request();
    host->set_request_id(1008);
    host->set_request_voting(true);

    context::Context ctx;
    ASSERT_EQ(error::OK, core3->Receive(&ctx, msg));
    auto out = PassMessages(cores, core3.get());
    ASSERT_EQ(1, out[core3->ID()].size());
    auto resp = out[core3->ID()][0].h2e_response();
    ASSERT_EQ(resp.request_id(), 1008);
    ASSERT_EQ(resp.inner_case(), HostToEnclaveResponse::kStatus);
    ASSERT_EQ(resp.status(), error::OK);

    std::set<peerid::PeerID> want{ core2->ID(), core3->ID() };
    ASSERT_EQ(want, core1->GroupTimeParticipants(&ctx));
  }

}

}  // namespace svr2::core
