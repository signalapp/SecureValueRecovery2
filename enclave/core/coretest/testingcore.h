// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only


#ifndef __SVR2_CORE_CORETEST_TESTINGCORE_H__
#define __SVR2_CORE_CORETEST_TESTINGCORE_H__

#include <deque>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "core/core.h"
#include "env/test/test.h"
#include "proto/enclaveconfig.pb.h"
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"
#include "util/log.h"
#include "proto/client.pb.h"

namespace svr2::core::test {
class TestingCore;
class ReplicaGroup;
class TestingClient;
using RequestID = uint64_t;
using TestingCoreMap = std::map<peerid::PeerID, TestingCore*>;
using PeerMessageMap = std::map<peerid::PeerID, std::vector<PeerMessage>>;
using OpenClientRequests = std::map<RequestID, TestingClient*>;

/*
This class wraps the basic actions of a `Core` and plays much
of the role the host plays in a real deployment - wrapping requests,
forwarding messages to peers and clients, etc.
*/
class TestingCore {
  enum class State { ACTIVE, PAUSED_SAVE_MSGS, PAUSED_DROP_MSGS, STOPPED };

 public:
  TestingCore(ReplicaGroup& replica_group);

  error::Error Init() { return error::OK; }

  uint64_t next_request_id() { return ++(next_request_id_); }
  peerid::PeerID ID() const { return core_->ID(); }
  const std::map<peerid::PeerID, std::vector<PeerMessage>>& peer_messages_out()
      const {
    return peer_messages_out_;
  }

  const std::deque<HostToEnclaveResponse>& host_to_enclave_responses() const {
    return h2e_responses_out_;
  }

  std::deque<HostToEnclaveResponse> take_host_to_enclave_responses() {
    return std::move(h2e_responses_out_);
  }
  const std::deque<UntrustedMessage>& input_messages() const {
    return input_messages_;
  }

  bool leader() const { return core_->leader() && active(); }
  bool serving() const { return core_->serving() && active(); }
  bool voting() const { return core_->voting() && active(); }
  bool active() const { return state_ == State::ACTIVE; }
  size_t num_voting() const { return core_->num_voting(); }
  size_t num_serving() const { return core_->num_members(); }
  std::set<peerid::PeerID> all_replicas() const { return core_->all_replicas(); }

  void Stop() { state_ = State::STOPPED; }
  void Pause(bool drop_msgs) {
    state_ = drop_msgs ? State::PAUSED_DROP_MSGS : State::PAUSED_SAVE_MSGS;
  }
  void Reactivate() { state_ = State::ACTIVE; }

  error::Error ProcessIncomingMessage();
  error::Error ProcessAllIncomingMessages();
  error::Error ForwardOutgoingMessages();
  error::Error ProcessNextH2EResponse();
  error::Error ProcessAllH2EResponses();

  // Host to Enclave commands
  error::Error ResetPeer(peerid::PeerID peer_id);
  error::Error ConnectPeer(peerid::PeerID peer_id);
  error::Error PingPeer(peerid::PeerID peer_id);
  error::Error GetEnclaveStatus();
  error::Error TimerTick();
  error::Error CreateNewRaftGroup();
  error::Error JoinRaft(peerid::PeerID peer_id);
  error::Error RequestVoting();
  error::Error Reconfigure(const enclaveconfig::EnclaveConfig& config);
  error::Error DeleteBackup(const std::string& client_authenticated_id);
  error::Error RaftRemoval();
  error::Error UpdateMinimums(const minimums::MinimumLimits& lim);
  error::Error DBRequest(const DatabaseRequest& req);

  // Peer communication
  error::Error AddPeerMessage(PeerMessage&& peer_message);

  // Client communication
  // handshake
  error::Error NewClientRequest(TestingClient* client,
                                std::string client_authenticated_id);

  // Backup or Restore
  error::Error ExistingClientRequest(TestingClient* client, uint64_t client_id,
                                     std::string data);

  EnclaveReplicaStatus TakeExpectedEnclaveStatusReply();
 private:
  std::unique_ptr<Core> core_;
  ReplicaGroup& replica_group_;
  enclaveconfig::EnclaveConfig config_;

  std::deque<UntrustedMessage> input_messages_;
  std::deque<HostToEnclaveResponse> h2e_responses_out_;
  PeerMessageMap peer_messages_out_;
  OpenClientRequests open_client_requests_;

  uint64_t next_request_id_{0};
  uint64_t timer_secs_{1};
  State state_{State::ACTIVE};
};

};  // namespace svr2::core::test

#endif  // __SVR2_CORE_CORETEST_TESTINGCORE_H__
