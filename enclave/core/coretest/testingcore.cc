// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "testingcore.h"

#include <gtest/gtest.h>

#include "util/bytes.h"

#include "replicagroup.h"
#include "testingclient.h"

namespace svr2::core::test {

TestingCore::TestingCore(ReplicaGroup& replica_group)
    : replica_group_(replica_group) {
  context::Context ctx;
  enclaveconfig::InitConfig cfg = replica_group.get_init_config();
  cfg.set_initial_timestamp_unix_secs(timer_secs_);
  auto [core, err] = Core::Create(&ctx, cfg);
  if (err != error::OK) {
    LOG(ERROR) << "Could not create core: " << err;
    CHECK(false);
  }
  core_ = std::move(core);
}

error::Error TestingCore::ProcessIncomingMessage() {
  error::Error result = error::OK;
  if (!active() || input_messages_.empty()) {
    return result;
  }

  // send the commands and other messages to the enclave
  LOG(VERBOSE) << "Core " << ID() << " processing first of "
               << input_messages_.size() << " messages";
  context::Context ctx;

  // take the input message
  auto msg = std::move(input_messages_.front());
  input_messages_.pop_front();
  auto err = core_->Receive(&ctx, msg);
  if (err != error::OK) {
    // clear the messages and return error
    env::test::SentMessages();
    return err;
  }

  // get the responses
  auto response_msgs = env::test::SentMessages();

  // process according to type
  peerid::PeerID to;
  PeerMessage peer_msg;
  for (auto& response : response_msgs) {
    switch (response.inner_case()) {
      case EnclaveMessage::kPeerMessage:
        peer_msg = std::move(*response.mutable_peer_message());

        // read who this message is *to*
        to.FromString(peer_msg.peer_id());

        // Now reset the peer_id in the message to our ID so the
        // recipient knows who it is *from*
        ID().ToString(peer_msg.mutable_peer_id());
        peer_messages_out_[to].emplace_back(std::move(peer_msg));
        break;
      case EnclaveMessage::kH2EResponse:
        h2e_responses_out_.emplace_back(response.h2e_response());
        break;
      default:
        CHECK(false);
    }
  }
  return error::OK;
}

error::Error TestingCore::ProcessAllIncomingMessages() {
  while (!input_messages_.empty()) {
    RETURN_IF_ERROR(ProcessIncomingMessage());
  }
  return error::OK;
}

error::Error TestingCore::ProcessNextH2EResponse() {
  auto h2e_response = std::move(h2e_responses_out_.front());
  h2e_responses_out_.pop_front();
  auto request_id = h2e_response.request_id();
  auto cl = open_client_requests_[request_id];
  switch (h2e_response.inner_case()) {
    case HostToEnclaveResponse::kStatus:
      if (error::OK != h2e_response.status()) {
        LOG(DEBUG) << ID() << " response for request " << request_id << " error: " << h2e_response.status();
        return h2e_response.status();
      }
      break;
    case HostToEnclaveResponse::kNewClientReply:
      cl->HandleNewClientReply(h2e_response.new_client_reply());
      break;
    case HostToEnclaveResponse::kExistingClientReply:
      cl->HandleExistingClientReply(h2e_response.existing_client_reply());
      break;
    case HostToEnclaveResponse::kGetEnclaveStatusReply:
      break;
    default:
      CHECK(false);
  }
  return error::OK;
}

error::Error TestingCore::ProcessAllH2EResponses() {
  while (!h2e_responses_out_.empty()) {
    RETURN_IF_ERROR(ProcessNextH2EResponse());
  }
  return error::OK;
}

error::Error TestingCore::AddPeerMessage(PeerMessage&& peer_message) {
  if (state_ == State::ACTIVE || state_ == State::PAUSED_SAVE_MSGS) {
    peerid::PeerID other_id;
    other_id.FromString(peer_message.peer_id());
    LOG(VERBOSE) << " core " << ID() << " receiving message from " << other_id;
    ::svr2::UntrustedMessage req;
    *req.mutable_peer_message() = std::move(peer_message);
    input_messages_.emplace_back(std::move(req));
  }
  return error::OK;
}

error::Error TestingCore::ForwardOutgoingMessages() {
  for (auto& [to, msgs] : peer_messages_out_) {
    for (auto& msg : msgs) {
      RETURN_IF_ERROR(replica_group_.SendMessage(to, msg));
    }
  }
  peer_messages_out_.clear();
  return error::OK;
}

error::Error TestingCore::ResetPeer(peerid::PeerID peer_id) {
  LOG(VERBOSE) << "resetpeerreq " << core_->ID() << " -> " << peer_id;
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  peer_id.ToString(host->mutable_reset_peer_id());
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::ConnectPeer(peerid::PeerID peer_id) {
  LOG(VERBOSE) << "connectpeerreq " << core_->ID() << " -> " << peer_id;
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  peer_id.ToString(host->mutable_connect_peer_id());
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::PingPeer(peerid::PeerID peer_id) {
  LOG(VERBOSE) << "pingreq " << core_->ID() << " -> " << peer_id;
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  peer_id.ToString(host->mutable_ping_peer()->mutable_peer_id());
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::GetEnclaveStatus() {
  LOG(VERBOSE) << "getenclavestatus " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());

  host->set_get_enclave_status(true);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::TimerTick() {
  ++timer_secs_;
  LOG(VERBOSE) << "timertick " << core_->ID() << " secs: " << timer_secs_;
  UntrustedMessage msg;
  msg.mutable_timer_tick()->set_new_timestamp_unix_secs(timer_secs_);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::CreateNewRaftGroup() {
  LOG(VERBOSE) << "createnewraftgroup " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->set_create_new_raft_group(true);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::JoinRaft(peerid::PeerID peer_id) {
  if (!peer_id.Valid()) {
    return error::Peers_InvalidID;
  }
  LOG(VERBOSE) << "joinraftreq " << core_->ID() << " -> " << peer_id;
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  auto req = host->mutable_join_raft();
  peer_id.ToString(req->mutable_peer_id());
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}
error::Error TestingCore::RequestVoting() {
  LOG(VERBOSE) << "requestvoting " << core_->ID();

  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->set_request_voting(true);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::Reconfigure(const enclaveconfig::EnclaveConfig& config) {
  LOG(VERBOSE) << "reconfigure " << core_->ID();
  config_ = config;
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->mutable_reconfigure()->MergeFrom(config);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::RaftRemoval() {
  LOG(VERBOSE) << "raft_removal " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->set_request_removal(true);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::DeleteBackup(const std::string& client_authenticated_id) {
  LOG(VERBOSE) << "deletebackup " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  client::Request delete_;
  delete_.mutable_delete_();
  CHECK(delete_.SerializeToString(host->mutable_database_request()->mutable_request()));
  host->mutable_database_request()->set_authenticated_id(client_authenticated_id);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::UpdateMinimums(const minimums::MinimumLimits& lim) {
  LOG(VERBOSE) << "update_minimums " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->mutable_update_minimums()->MergeFrom(lim);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::DBRequest(const DatabaseRequest& d) {
  LOG(VERBOSE) << "database_request " << core_->ID();
  UntrustedMessage msg;
  auto host = msg.mutable_h2e_request();
  host->set_request_id(next_request_id());
  host->mutable_database_request()->MergeFrom(d);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

error::Error TestingCore::NewClientRequest(
    TestingClient* client, std::string client_authenticated_id) {
  LOG(VERBOSE) << "newclient " << core_->ID();

  UntrustedMessage msg;
  auto h2e_req = msg.mutable_h2e_request();
  auto new_client_req = h2e_req->mutable_new_client();
  auto request_id = next_request_id();
  open_client_requests_[request_id] = client;
  h2e_req->set_request_id(request_id);

  new_client_req->set_client_authenticated_id(client_authenticated_id);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

// Backup or Restore
error::Error TestingCore::ExistingClientRequest(TestingClient* client,
                                                uint64_t client_id,
                                                std::string data) {
  LOG(VERBOSE) << "existingclient " << core_->ID();

  UntrustedMessage msg;
  auto h2e_req = msg.mutable_h2e_request();
  auto existing_client_req = h2e_req->mutable_existing_client();
  auto request_id = next_request_id();
  open_client_requests_[request_id] = client;
  h2e_req->set_request_id(request_id);

  existing_client_req->set_client_id(client_id);
  existing_client_req->set_data(data);
  input_messages_.emplace_back(std::move(msg));
  return error::OK;
}

EnclaveReplicaStatus TestingCore::TakeExpectedEnclaveStatusReply() {
  auto& h2e_response = h2e_responses_out_[0];
  EXPECT_EQ(h2e_response.inner_case(), HostToEnclaveResponse::kGetEnclaveStatusReply);
  auto result = std::move(h2e_response.get_enclave_status_reply());
  h2e_responses_out_.pop_front();
  return result;
}

};  // namespace svr2::core::test
