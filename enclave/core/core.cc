// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "core/core.h"

#include <utility>

#include "proto/enclaveconfig.pb.h"
#include "util/macros.h"
#include "env/env.h"
#include "sender/sender.h"
#include "context/context.h"
#include "util/log.h"
#include "util/bytes.h"
#include "util/constant.h"
#include "util/endian.h"
#include "core/internal.h"
#include "metrics/metrics.h"
#include "hmac/hmac.h"
#include "util/hex.h"

#define IDLOG(x) LOG(x) << "(" << ID().DebugString() << ") "

namespace svr2::core {

namespace {

void LogRaftGroupConfig(const std::string& name, const enclaveconfig::RaftGroupConfig& c) {
  LOG(INFO) << "RaftGroupConfig(" << name << "):"
    << " min_voting_replicas:" << c.min_voting_replicas()
    << " max_voting_replicas:" << c.max_voting_replicas()
    << " super_majority:" << c.super_majority()
    << " attestation_timeout:" << c.attestation_timeout()
    << " db_version:" << c.db_version()
    << " simulated:" << c.simulated();
}

bool RaftGroupConfigsEqualExceptForGroupID(const enclaveconfig::RaftGroupConfig& a, const enclaveconfig::RaftGroupConfig& b) {
  LOG(INFO) << "Comparing group configs:";
  LogRaftGroupConfig("a", a);
  LogRaftGroupConfig("b", b);
  return
      a.min_voting_replicas() == b.min_voting_replicas() &&
      a.max_voting_replicas() == b.max_voting_replicas() &&
      a.super_majority() == b.super_majority() &&
      a.db_version() == b.db_version() &&
      a.attestation_timeout() == b.attestation_timeout() &&
      a.simulated() == b.simulated();
}

error::Error ValidateRaftGroupConfig(const enclaveconfig::RaftGroupConfig& c) {
  if (c.min_voting_replicas() > c.max_voting_replicas()) { return COUNTED_ERROR(Core_RaftGroupConfigMinReplicasGreaterThanMaxReplicas); }
  if (c.min_voting_replicas() < 1) { return COUNTED_ERROR(Core_RaftGroupConfigMinReplicasTooSmall); }
  if (c.attestation_timeout() < 1) { return COUNTED_ERROR(Core_RaftGroupConfigAttestationTimeoutTooSmall); }
  auto d = db::DB::New(c.db_version());
  if (d.get() == nullptr) { return COUNTED_ERROR(Core_DBVersionInvalid); }
  return error::OK;
}

enclaveconfig::EnclaveConfig DefaultEnclaveConfig() {
  enclaveconfig::EnclaveConfig def;
  def.set_e2e_txn_timeout_ticks(60);
  auto raft = def.mutable_raft();
  raft->set_election_ticks(32);
  raft->set_heartbeat_ticks(15);
  raft->set_replication_chunk_bytes(1<<20);
  raft->set_replica_voting_timeout_ticks(60);
  raft->set_replica_membership_timeout_ticks(300);
  raft->set_log_max_bytes(1<<30);
  raft->set_replication_pipeline(4);
  return def;
}

void ReplyWithError(context::Context* ctx, internal::TransactionID tx, error::Error err) {
  EnclaveMessage* out = ctx->Protobuf<EnclaveMessage>();
  auto resp = out->mutable_h2e_response();
  resp->set_request_id(tx);
  resp->set_status(err);
  if (err != error::OK) {
    LOG(WARNING) << "Responding to host request " << tx << " with error: " << err;
  }
  sender::Send(ctx, *out);
}

static bool ContainsMe(const peerid::PeerID& me, const raft::ReplicaGroup& group) {
  std::string me_str;
  me.ToString(&me_str);
  for (int i = 0; i < group.replicas_size(); i++) {
    auto replica = group.replicas(i);
    if (replica.peer_id() == me_str) return true;
  }
  return false;
}

}  // namespace
 
Core::Core(const enclaveconfig::RaftGroupConfig& group_config) : raft_config_template_(group_config), db_version_(group_config.db_version()), db_protocol_(db::DB::New(group_config.db_version())->P()), e2e_txn_id_(0) {
}

std::pair<std::unique_ptr<Core>, error::Error> Core::Create(
    context::Context* ctx,
    const enclaveconfig::InitConfig& provided_config) {
  LOG(INFO) << "Creating core";
  auto config = DefaultEnclaveConfig();
  config.MergeFrom(provided_config.enclave_config());
  error::Error err = error::OK;
  LOG(INFO) << "Validating";
  if (error::OK != (err = Core::ValidateConfig(config))) {
    LOG(INFO) << "Validation error: " << err;
    return std::make_pair(nullptr, err);
  }
  if (error::OK != (err = ValidateRaftGroupConfig(provided_config.group_config()))) {
    LOG(INFO) << "Raft group config validation error: " << err;
    return std::make_pair(nullptr, err);
  }
  LOG(INFO) << "Initializing";
  std::unique_ptr<Core> core(new Core(provided_config.group_config()));
  if (error::OK != (err = core->Init(ctx, config, provided_config.initial_timestamp_unix_secs()))) {
    return std::make_pair(nullptr, err);
  }
  return std::make_pair(std::move(core), error::OK);
}

error::Error Core::Init(context::Context* ctx, const enclaveconfig::EnclaveConfig& config, util::UnixSecs initial_timestamp_unix_secs) {
  RETURN_IF_ERROR(Core::ValidateConfig(config));

  // The ClientManager will obtain evidence and endorsements as needed.
  LOG(INFO) << "Setting up client DHState";
  auto client_dh = client::ClientManager::NewDHState();
  if (client_dh.get() == nullptr) {
    return COUNTED_ERROR(Core_InitClientDHState);
  }

  // The PeerManager will create a key pair, set the public key as its ID, and obtain attestation
  // evidence and endorsements as needed.
  LOG(INFO) << "Setting up peer DHState";
  auto peer_manager = std::make_unique<peers::PeerManager>();
  RETURN_IF_ERROR(peer_manager->Init(ctx));

  LOG(INFO) << "Setting up remaining core";
  {
    ACQUIRE_LOCK(config_mu_, ctx, lock_core_config);
    enclave_config_ = config;
  }
  peer_manager_ = std::move(peer_manager);
  client_manager_ = std::make_unique<client::ClientManager>(std::move(client_dh));
  clock_.SetLocalTime(initial_timestamp_unix_secs);
  peer_manager_->SetPeerAttestationTimestamp(ctx, initial_timestamp_unix_secs, raft_config_template_.attestation_timeout());

  SendTimestampToAll(ctx);

  return error::OK;
}

error::Error Core::ValidateConfig(const enclaveconfig::EnclaveConfig& config) {
  auto raft = config.raft();
  if (raft.election_ticks() == 0) { return COUNTED_ERROR(Config_ElectionTicks); }
  if (raft.heartbeat_ticks() >= raft.election_ticks()) { return COUNTED_ERROR(Config_HeartbeatVsElectionTicks); }
  if (raft.replication_chunk_bytes() < (1024)) { return COUNTED_ERROR(Config_ReplicationChunk); }
  if (raft.replica_voting_timeout_ticks() <= raft.election_ticks()) { return COUNTED_ERROR(Config_ReplicaTimeout); }
  if (raft.replica_membership_timeout_ticks() <= raft.replica_voting_timeout_ticks()) { return COUNTED_ERROR(Config_ReplicaTimeout); }
  if (raft.log_max_bytes() < 1024) { return COUNTED_ERROR(Config_LogMaxBytes); }
  if (raft.replication_pipeline() <= 0 || raft.replication_pipeline() >= UINT32_MAX) { return COUNTED_ERROR(Config_ReplicationPipeline); }
  if (config.e2e_txn_timeout_ticks() < 1) { return COUNTED_ERROR(Config_E2ETransactionTimeout); }
  return error::OK;
}

error::Error Core::ValidateConfigChange(const enclaveconfig::EnclaveConfig& old_config, const enclaveconfig::EnclaveConfig& new_config) {
  RETURN_IF_ERROR(ValidateConfig(new_config)); 
  return error::OK;
}

enclaveconfig::EnclaveConfig* Core::enclave_config(context::Context* ctx) const {
  ACQUIRE_LOCK(config_mu_, ctx, lock_core_config);
  auto cfg = ctx->Protobuf<enclaveconfig::EnclaveConfig>();
  cfg->MergeFrom(enclave_config_);
  return cfg;
}

error::Error Core::Receive(context::Context* ctx, const UntrustedMessage& msg) {
  switch (msg.inner_case()) {
    case UntrustedMessage::kH2ERequest: {
      MEASURE_CPU(ctx, cpu_core_host_msg);
      COUNTER(core, host_requests_received)->Increment();
      return HandleHostToEnclave(ctx, msg.h2e_request());
    }
    case UntrustedMessage::kTimerTick:
      COUNTER(core, timer_ticks_received)->Increment();
      HandleTimerTick(ctx, msg.timer_tick());
      return error::OK;
    case UntrustedMessage::kResetPeer:{
      peerid::PeerID peer_id;
      RETURN_IF_ERROR(peer_id.FromString(msg.reset_peer().peer_id()));
      return peer_manager_->ResetPeer(ctx, peer_id);
    }
    case UntrustedMessage::kPeerMessage: {
      MEASURE_CPU(ctx, cpu_core_peer_msg);
      COUNTER(core, peer_msgs_received)->Increment();
      return HandlePeerMessage(ctx, msg);
    }
    default:
      COUNTER(core, invalid_msgs_received)->Increment();
      return error::General_Unimplemented;
  }
}

error::Error Core::HandleHostToEnclave(context::Context* ctx, const HostToEnclaveRequest& msg) {
  internal::TransactionID tx = msg.request_id();
  if (tx == 0) {
    return COUNTED_ERROR(Core_HostToEnclaveTransactionID);
  }
  IDLOG(DEBUG) << "request " << tx << " is " << msg.inner_case();
  switch (msg.inner_case()) {
    case HostToEnclaveRequest::kNewClient: {
      MEASURE_CPU(ctx, cpu_core_client_msg);
      HandleNewClient(ctx, msg.new_client(), tx);
    } return error::OK;
    case HostToEnclaveRequest::kExistingClient: {
      MEASURE_CPU(ctx, cpu_core_client_msg);
      error::Error err = HandleExistingClient(ctx, msg.existing_client(), tx);
      // We never let client errors get us down, but we do close down clients
      // with abandon if they encounter errors.
      if (err != error::OK) {
        client_manager_->RemoveClient(ctx, msg.existing_client().client_id());
        ReplyWithError(ctx, tx, err);
      }
    } return error::OK;  // return OK, even if we closed the client.
    case HostToEnclaveRequest::kCloseClient: {
      MEASURE_CPU(ctx, cpu_core_client_msg);
      client_manager_->RemoveClient(ctx, msg.close_client().client_id());
      ReplyWithError(ctx, tx, error::OK);
    } return error::OK;
    case HostToEnclaveRequest::kCreateNewRaftGroup: {
      HandleCreateNewRaftGroupRequest(ctx, tx);
    } return error::OK;
    case HostToEnclaveRequest::kJoinRaft: {
      HandleJoinRaft(ctx, msg.join_raft(), tx);
    } return error::OK;
    case HostToEnclaveRequest::kPingPeer: {
      peerid::PeerID peer_id;
      error::Error peer_id_err = peer_id.FromString(msg.ping_peer().peer_id());
      if (peer_id_err != error::OK) {
        ReplyWithError(ctx, tx, peer_id_err);
        return error::OK;
      }
      auto req = ctx->Protobuf<e2e::TransactionRequest>();
      req->set_ping(true);
      SendE2ETransaction(ctx, peer_id, *req, true,
          [tx](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
            ReplyWithError(ctx, tx, err);
          });
    } return error::OK;
    case HostToEnclaveRequest::kRefreshAttestation: {
      error::Error peer_err = peer_manager_->RefreshAttestation(ctx);
      error::Error client_err = HandleRefreshAttestation(ctx, msg.refresh_attestation().rotate_client_key());
      ReplyWithError(ctx, tx, peer_err != error::OK ? peer_err : client_err);
    } return error::OK;
    case HostToEnclaveRequest::kRequestVoting: {
      ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
      if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
        ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
      } else if (raft_.loaded.raft->voting()) {
        ReplyWithError(ctx, tx, COUNTED_ERROR(Core_VotingRequestedForVotingMember));
      } else if (!raft_.loaded.raft->leader().has_value()) {
        ReplyWithError(ctx, tx, COUNTED_ERROR(Core_LeaderUnknown));
      } else {
        auto txn_req = ctx->Protobuf<e2e::TransactionRequest>();
        txn_req->set_raft_voting_request(true);
        SendE2ETransaction(ctx, *raft_.loaded.raft->leader(), *txn_req, true,
            [tx](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
              ReplyWithError(ctx, tx, err);
            });
      }
    } return error::OK;
    case HostToEnclaveRequest::kGetEnclaveStatus: {
      auto out = ctx->Protobuf<EnclaveMessage>();
      auto resp = out->mutable_h2e_response();
      resp->set_request_id(tx);
      auto [replica_status, err] = HandleGetEnclaveStatus(ctx);
      if (err != error::OK) {
        ReplyWithError(ctx, tx, err);
      } else {
        resp->mutable_get_enclave_status_reply()->MergeFrom(replica_status);
        sender::Send(ctx, *out);
      }
    } return error::OK;
    case HostToEnclaveRequest::kRequestMetrics: {
      MEASURE_CPU(ctx, cpu_core_metrics);
      env::environment->UpdateEnvStats();
      EnclaveMessage* out = ctx->Protobuf<EnclaveMessage>();
      auto resp = out->mutable_h2e_response();
      resp->set_request_id(tx);
      *resp->mutable_metrics_reply() = metrics::AllAsPB();
      sender::Send(ctx, *out);
    } return error::OK;
    case HostToEnclaveRequest::kDatabaseRequest: {
      MEASURE_CPU(ctx, cpu_core_host_database_req);
      RETURN_IF_ERROR(HandleHostDatabaseRequest(ctx, tx, msg.database_request()));
    } return error::OK;
    case HostToEnclaveRequest::kReconfigure: {
      auto err = HandleReconfigure(ctx, tx, msg.reconfigure());
      ReplyWithError(ctx, tx, err);
    } return error::OK;
    case HostToEnclaveRequest::kSetLogLevel: {
      if (msg.set_log_level() >= ::svr2::enclaveconfig::LOG_LEVEL_MAX) {
        ReplyWithError(ctx, tx, error::Core_InvalidLogLevel);
      } else {
        util::SetLogLevel(msg.set_log_level());
        ReplyWithError(ctx, tx, error::OK);
      }
    } return error::OK;
    case HostToEnclaveRequest::kRelinquishLeadership: {
      HandleRelinquishLeadership(ctx, tx);
    } return error::OK;
    case HostToEnclaveRequest::kRequestRemoval: {
      HandleHostRequestedRaftRemoval(ctx, tx);
    } return error::OK;
    case HostToEnclaveRequest::kHashes: {
      auto err = HandleHostHashes(ctx, tx);
      if (err != error::OK) { ReplyWithError(ctx, tx, err); }
    } return error::OK;
    default:
      return error::General_Unimplemented;
  }
}

void Core::HandleNewClient(context::Context* ctx, const NewClientRequest& msg, internal::TransactionID tx) {
  auto [client, err] = client_manager_->NewClient(ctx, msg.client_authenticated_id());
  if (err != error::OK) {
    ReplyWithError(ctx, tx, err);
    COUNTER(core, new_client_failure)->Increment();
    return;
  }
  auto out = ctx->Protobuf<EnclaveMessage>();
  auto resp = out->mutable_h2e_response();
  resp->set_request_id(tx);
  auto new_client = resp->mutable_new_client_reply();
  new_client->set_client_id(client->ID());
  *new_client->mutable_handshake_start() = client->MovedHandshakeStart();
  sender::Send(ctx, *out);
  COUNTER(core, new_client_success)->Increment();
}

error::Error Core::HandleExistingClient(context::Context* ctx, const ExistingClientRequest& msg, internal::TransactionID tx) {
  client::ClientID client_id = msg.client_id();
  client::Client* c = client_manager_->GetClient(ctx, client_id);
  if (c == nullptr) {
    return COUNTED_ERROR(Core_ClientNotFound);
  }
  if (c->Handshaking()) {
    auto [handshake, err] = c->FinishHandshake(ctx, msg.data());
    RETURN_IF_ERROR(err);
    auto out = ctx->Protobuf<EnclaveMessage>();
    auto resp = out->mutable_h2e_response();
    resp->set_request_id(tx);
    resp->mutable_existing_client_reply()->set_data(handshake);
    sender::Send(ctx, *out);
    return error::OK;
  }
  auto request = db_protocol_->RequestPB(ctx);
  RETURN_IF_ERROR(c->DecryptRequest(ctx, msg.data(), request));
  auto [log, err] = db_protocol_->LogPBFromRequest(ctx, std::move(*request), c->authenticated_id());
  RETURN_IF_ERROR(err);
  RETURN_IF_ERROR(db_protocol_->ValidateClientLog(*log));
  std::string serialized;
  if (!log->SerializeToString(&serialized)) {
    return COUNTED_ERROR(Core_SerializeClientLog);
  }
  return RaftWriteLogTransaction(ctx, serialized, ClientLogTransaction(ctx, client_id, tx));
}

void Core::HandleCreateNewRaftGroupRequest(context::Context* ctx, internal::TransactionID tx) {
  LOG(INFO) << "Attempting to create new raft group";
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_NO_STATE) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
  }
  enclaveconfig::RaftGroupConfig cfg = raft_config_template_;
  uint8_t group_id_bytes[8];
  error::Error gid_err = env::environment->RandomBytes(group_id_bytes, sizeof(group_id_bytes));
  if (gid_err != error::OK) {
    ReplyWithError(ctx, tx, gid_err);
  }
  raft::GroupId group_id = util::BigEndian64FromBytes(group_id_bytes);
  cfg.set_group_id(group_id);
  cfg.set_db_version(db_version_);

  raft_.state = svr2::RAFTSTATE_LOADED_PART_OF_GROUP;
  enclaveconfig::RaftConfig raft_config = enclave_config(ctx)->raft();
  raft_.loaded = {
    .group_config = cfg,
    .raft = std::make_unique<raft::Raft>(
        group_id,
        peer_manager_->ID(),
        raft::Membership::First(peer_manager_->ID()),
        std::make_unique<raft::Log>(raft_config.log_max_bytes()),
        raft_config,
        false,
        cfg.super_majority()),  // committed_log
    .db = db::DB::New(db_version_),
    .db_last_applied_log = 0,
  };
  GAUGE(core, last_index_applied_to_db)->Set(0);
  RaftStep(ctx);
  ReplyWithError(ctx, tx, error::OK);
}

void Core::HandleJoinRaft(context::Context* ctx, const JoinRaftRequest& msg, internal::TransactionID tx) {
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
    return;
  }
  peerid::PeerID peer;
  error::Error peer_err = peer.FromString(msg.peer_id());
  if (peer_err != error::OK) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
    return;
  }
  raft_.ClearState();
  raft_.state = svr2::RAFTSTATE_WAITING_FOR_FIRST_CONNECTION;
  raft_.waiting_for_first_connection = {
    .peer = peer,
    .join_tx = tx,
  };

  switch (peer_manager_->PeerState(ctx, peer)) {
    case PEER_CONNECTED:
      JoinRaftFromFirstPeer(ctx);
      break;
    case PEER_CONNECTING:
      break;
    default:
      peer_manager_->ConnectToPeer(ctx, peer);
      break;
  }
}

void Core::JoinRaftFromFirstPeer(context::Context* ctx) {
  CHECK(raft_.state == svr2::RAFTSTATE_WAITING_FOR_FIRST_CONNECTION);
  internal::TransactionID tx = raft_.waiting_for_first_connection.join_tx;
  peerid::PeerID peer = raft_.waiting_for_first_connection.peer;
  IDLOG(VERBOSE) << "requesting to join raft from peer " << peer << " tx=" << tx;
  auto req = ctx->Protobuf<e2e::TransactionRequest>();
  req->set_get_raft(true);
  SendE2ETransaction(
      ctx, peer, *req, true,
      [this, tx, peer](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp){
        if (err != error::OK) {
          ReplyWithError(ctx, tx, err);
          return;
        }
        ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);

        // We cleared the RaftState before sending this request and we will only proceed with this 
        // callback if no intermediate action has changed the state.
        if (raft_.state != svr2::RAFTSTATE_WAITING_FOR_FIRST_CONNECTION) {
          ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
          return;
        }
        // Since the state is NO_STATE we are guaranteed that the raft_ has default values (no 
        // actions change raft_ with out changing raft_state).
        
        auto got = resp->get_raft();
        enclaveconfig::RaftGroupConfig group_config_equality_check = got.group_config();
        group_config_equality_check.clear_group_id();
        if (!RaftGroupConfigsEqualExceptForGroupID(raft_config_template_, group_config_equality_check)) {
          ReplyWithError(ctx, tx, COUNTED_ERROR(Core_GroupConfigMismath));
          return;
        }
        if (got.replica_group().replicas_size() == 0) {
          ReplyWithError(ctx, tx, COUNTED_ERROR(Core_ReceivedEmptyReplicaGroup));
          return;
        }
        auto [mem, mem_err] = raft::Membership::FromProto(got.replica_group());
        if (mem_err != error::OK) {
          ReplyWithError(ctx, tx, mem_err);
          return;
        }
        for (int i = 0; i < got.replica_group().replicas_size(); i++) {
          peerid::PeerID p;
          const auto& replica = got.replica_group().replicas(i);
          err = p.FromString(replica.peer_id());
          if (err != error::OK) {
            ReplyWithError(ctx, tx, err);
            return;
          }
          err = peer_manager_->MaybeConnectToPeer(ctx, p);
          if (err != error::OK) {
            ReplyWithError(ctx, tx, err);
            return;
          }
        }

        LOG(INFO) << "received raft information, switching to loading state and starting replication";
        raft_.ClearState();
        raft_.state = svr2::RAFTSTATE_LOADING;
        raft_.loading = {
          .group_config = got.group_config(),
          .replica_group = got.replica_group(),
          .log = std::make_unique<raft::Log>(enclave_config(ctx)->raft().log_max_bytes()),
          .db = db::DB::New(db_version_),
          .mem = std::move(mem),
          .load_from = peer,
          .join_tx = tx,
        };

        // Reset client attestation based on new group config.
        if (error::OK != (err = client_manager_->RefreshAttestation(ctx, raft_.loading.group_config))) {
          ReplyWithError(ctx, tx, err);
          return;
        }

        RequestRaftReplication(ctx);
      });
}

void Core::RequestRaftReplication(context::Context* ctx) {
  if (raft_.state != svr2::RAFTSTATE_LOADING) {
    IDLOG(WARNING) << "RequestRaftReplication called while state is " << raft_.state;
    return;
  }
  if (!raft_.loading.started) {
    size_t connected = 0;
    const auto& voting_replicas = raft_.loading.mem->voting_replicas();
    for (auto peer : peer_manager_->ConnectedPeers(ctx)) {
      if (voting_replicas.count(peer)) {
        connected++;
      }
    }
    size_t quorum = raft::Raft::quorum_size(
        voting_replicas.size(), raft_.loading.group_config.super_majority());
    if (connected < quorum) {
      IDLOG(VERBOSE) << "Still waiting for peer connections before starting load, have " << connected << ", need " << quorum;
      return;
    }
    raft_.loading.started = true;
  }
  uint8_t repl_id[8];
  env::environment->RandomBytes(repl_id, sizeof(repl_id));
  raft_.loading.replication_id = util::BigEndian64FromBytes(repl_id);
  internal::TransactionID tx = raft_.loading.join_tx;
  const peerid::PeerID& from = raft_.loading.load_from;

  auto req = ctx->Protobuf<e2e::TransactionRequest>();
  auto repl = req->mutable_replicate_state();
  repl->set_group_id(raft_.loading.group_config.group_id());
  repl->set_replication_id(raft_.loading.replication_id);

  IDLOG(VERBOSE) << "requesting replication from " << from;
  SendE2ETransaction(ctx, from, *req, false /* no timeout */,
      [this, from, tx](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
        if (err != error::OK) {
          // We've failed to replicate state.  For now, revert back to no state.
          LOG(ERROR) << "failed to replicate state from " << from << ": " << err;
          ReplyWithError(ctx, tx, err);
          return;
        }
        IDLOG(INFO) << "finished replicating database, fully loaded";
        ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
        PromoteRaftToLoaded(ctx);
      });
}

void Core::PromoteRaftToLoaded(context::Context* ctx) {
  internal::Loading loading = std::move(raft_.loading);
  raft_.ClearState();
  raft_.state = svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP;
  raft::LogIdx db_last_applied_log = loading.log->last_idx();
  raft_.loaded = {
    .group_config = loading.group_config,
    .raft = std::make_unique<raft::Raft>(
        loading.group_config.group_id(),
        peer_manager_->ID(),
        std::move(loading.mem),
        std::move(loading.log),
        enclave_config(ctx)->raft(),
        true,
        loading.group_config.super_majority()),  // committed_log
    .db = std::move(loading.db),
    .db_last_applied_log = db_last_applied_log,
  };
  GAUGE(core, last_index_applied_to_db)->Set(db_last_applied_log);
  RaftRequestMembership(ctx, loading.join_tx);
}

void Core::RaftRequestMembership(context::Context* ctx, internal::TransactionID tx) {
  // Never request membership unless in the correct state.
  CHECK(raft_.state == svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP);
  // We could be tricky and try to find out who the leader is.  Instead, we'll
  // just send our request to every member. Note that this will cause error
  // Raft_AppendEntryNotLeader (5004) to appear in the logs
  auto req = ctx->Protobuf<e2e::TransactionRequest>();
  req->set_raft_membership_request(true);
  // Set a timeout for if we fail to do this.
  timeout::Cancel cancel = timeout_.SetTimeout(ctx, enclave_config(ctx)->e2e_txn_timeout_ticks(), [this, tx](context::Context* ctx) {
    ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
    if (raft_.state == svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP) {
      RaftRequestMembership(ctx, tx);
    }
  });

  for (const auto& peer : raft_.loaded.raft->peers()) {
    IDLOG(VERBOSE) << "requesting raft membership from " << peer;
    SendE2ETransaction(ctx, peer, *req, true,
        [this, tx, cancel](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
          if (err != error::OK) {
            LOG(WARNING) << "Error requesting raft membership: " << err;
            return;
          }
          AddLogTransaction(ctx, resp->raft_membership_response(), [this, tx, cancel](
              context::Context* ctx,
              error::Error err,
              const raft::LogEntry* entry,
              const db::DB::Response* response) {
            // HandleRaftMembershipChange does the actual state changes, this
            // just tells our requester that we've succeeded.
            if (err == error::OK) {
              timeout_.CancelTimeout(ctx, cancel);
            }
            ReplyWithError(ctx, tx, err);
          });
        });
  }
}

error::Error Core::HandleRefreshAttestation(context::Context* ctx, bool rotate_key) {
  enclaveconfig::RaftGroupConfig config;
  {  // Copy current config out of Raft state.
    ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
    switch (raft_.state) {
      case svr2::RAFTSTATE_LOADING:
        config.MergeFrom(raft_.loading.group_config);
        break;
      case svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP:
      case svr2::RAFTSTATE_LOADED_PART_OF_GROUP:
        config.MergeFrom(raft_.loaded.group_config);
        break;
      default:
        return COUNTED_ERROR(Core_RefreshClientAttestationWithoutRaftConfig);
    }
  }
  return rotate_key
      ? client_manager_->RotateKeyAndRefreshAttestation(ctx, config)
      : client_manager_->RefreshAttestation(ctx, config);
}

std::pair<EnclaveReplicaStatus, error::Error> Core::HandleGetEnclaveStatus(context::Context* ctx) const {
  EnclaveReplicaStatus result;
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  result.set_raft_state(raft_.state);

  auto peers = peer_manager_->AllPeers(ctx);
  peers.insert(ID());
  peerid::PeerID leader;
  std::set<peerid::PeerID> all_replicas;
  std::set<peerid::PeerID> voting_replicas;
  if(raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    leader = raft_.loaded.raft->leader().value_or(peerid::PeerID());
    auto& membership = raft_.loaded.raft->membership();
    all_replicas = membership.all_replicas();
    voting_replicas = membership.voting_replicas();
  }
  for (auto peer_id : peers) {
    auto peer_status = result.add_peers();
    peer_status->set_peer_id(peer_id.AsString());
    peer_status->set_in_raft(all_replicas.count(peer_id));
    peer_status->set_is_voting(voting_replicas.count(peer_id) > 0);
    peer_status->set_is_leader(peer_id == leader);
    peer_manager_->PeerStatus(ctx, peer_id, peer_status->mutable_connection_status());
    peer_status->set_me(peer_id == ID());
      
    if (leader == ID() && peer_id != ID()) {
      auto err = raft_.loaded.raft->FollowerReplicationStatus(peer_id, peer_status->mutable_replication_status());
      if(err != error::OK) {
        return std::make_pair(result, err);
      }
    }
  }
  return std::make_pair(result, error::OK);
}

error::Error Core::HandleHostDatabaseRequest(context::Context* ctx, internal::TransactionID tx, const DatabaseRequest& req) {
  auto cli_req = db_protocol_->RequestPB(ctx);
  if (!cli_req->ParseFromString(req.request())) {
    return COUNTED_ERROR(Core_DeserializeHostDatabaseRequest);
  }
  auto [log, err] = db_protocol_->LogPBFromRequest(ctx, std::move(*cli_req), req.authenticated_id());
  RETURN_IF_ERROR(err);
  std::string serialized;
  if (!log->SerializeToString(&serialized)) {
    return COUNTED_ERROR(Core_SerializeClientLog);
  }
  return RaftWriteLogTransaction(ctx, serialized, [tx](
      context::Context* ctx,
      error::Error err,
      const raft::LogEntry* entry,
      const db::DB::Response* resp) {
    if (err == error::OK) {
      COUNTER(core, host_delete_success)->Increment();
    } else {
      COUNTER(core, host_delete_failure)->Increment();
    }
    ReplyWithError(ctx, tx, err);
  });
}

error::Error Core::HandleReconfigure(context::Context* ctx, internal::TransactionID tx, const enclaveconfig::EnclaveConfig& req) {
  auto new_config = DefaultEnclaveConfig();
  new_config.MergeFrom(req);
  {
    ACQUIRE_LOCK(config_mu_, ctx, lock_core_config);
    RETURN_IF_ERROR(ValidateConfigChange(enclave_config_, new_config));
    enclave_config_ = new_config;
  }
  {
    ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
    if (raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP
        || raft_.state == svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP) {
      raft_.loaded.raft->Reconfigure(new_config.raft());
    }
  }
  return error::OK;
}

void Core::HandleRelinquishLeadership(context::Context* ctx, internal::TransactionID tx) {
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != RAFTSTATE_LOADED_PART_OF_GROUP || !raft_.loaded.raft->is_leader()) {
    // We're already not the leader.
    ReplyWithError(ctx, tx, error::OK);
    return;
  }
  raft_.loaded.raft->RelinquishLeadership(ctx);
  // If we succeed in relinquishing leadership, then the log that's one past the
  // last one we have will have a term one greater than the most recent term.
  // Set up a watcher for that.
  raft::LogLocation loc;
  loc.set_idx(raft_.loaded.raft->log().next_idx());
  loc.set_term(raft_.loaded.raft->log().last_term() + 1);
  AddLogTransaction(ctx, loc, [tx](
      context::Context* ctx,
      error::Error err,
      const raft::LogEntry* entry,
      const db::DB::Response* resp) {
    ReplyWithError(ctx, tx, err);
  });
  RaftStep(ctx);
}

void Core::HandleHostRequestedRaftRemoval(context::Context* ctx, internal::TransactionID tx) {
  LOG(VERBOSE) << "HandleHostRequestedRaftRemoval";
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != RAFTSTATE_LOADED_PART_OF_GROUP) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_RaftState));
  } else if (raft_.loaded.raft->is_leader()) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_LeaderRemovingSelf));
  } else if (!raft_.loaded.raft->leader().has_value()) {
    ReplyWithError(ctx, tx, COUNTED_ERROR(Core_LeaderUnknown));
  } else {
    auto req = ctx->Protobuf<e2e::TransactionRequest>();
    req->set_raft_removal_request(true);
    auto peer = *raft_.loaded.raft->leader();
    SendE2ETransaction(ctx, peer, *req, true, [peer, tx](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
      LOG(INFO) << "RaftRemovalRequest to " << peer << ": " << err;
      ReplyWithError(ctx, tx, err);
    });
  }
}

error::Error Core::HandleHostHashes(context::Context* ctx, internal::TransactionID tx) {
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != RAFTSTATE_LOADED_PART_OF_GROUP &&
      raft_.state != RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP) {
    return COUNTED_ERROR(Core_RaftState);
  }
  auto db_hash = raft_.loaded.db->Hash(ctx);
  auto out = ctx->Protobuf<EnclaveMessage>();
  auto resp = out->mutable_h2e_response();
  resp->set_request_id(tx);
  auto hashes = resp->mutable_hashes();
  hashes->mutable_db_hash()->resize(32, ' ');
  std::copy(db_hash.begin(), db_hash.end(), hashes->mutable_db_hash()->data());
  hashes->set_commit_idx(raft_.loaded.db_last_applied_log);
  auto log = raft_.loaded.raft->log().At(raft_.loaded.db_last_applied_log).Entry();
  if (log == nullptr) {
    return COUNTED_ERROR(Core_LogNotFoundAtCommitIndex);
  }
  hashes->set_commit_hash_chain(log->hash_chain());
  sender::Send(ctx, *out);
  return error::OK;
}

void Core::HandleTimerTick(context::Context* ctx, const TimerTick& tick) {
  MEASURE_CPU(ctx, cpu_core_timer_tick);
  auto time = tick.new_timestamp_unix_secs();
  clock_.SetLocalTime(time);
  GAUGE(core, current_local_time)->Set(time);
  MaybeUpdateGroupTime(ctx);
  timeout_.TimerTick(ctx);
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    ConnectToRaftMembers(ctx);
    {
      MEASURE_CPU(ctx, cpu_core_raft_tick);
      raft_.loaded.raft->TimerTick(ctx);
    }
    if (raft_.loaded.raft->is_leader()) {
      raft::ReplicaGroup* next = NextReplicaGroup(ctx);
      if (next != nullptr) {
        auto [loc, err] = raft_.loaded.raft->ReplicaGroupChange(ctx, *next);
        // We expect errors to occur here, in cases where for example an existing
        // replica group change is already in progress, etc.
        LOG(INFO) << "attempt to change replica group returned " << err;
      }
    }
    RaftStep(ctx);
  }
}

void Core::MaybeUpdateGroupTime(context::Context* ctx) {
  MEASURE_CPU(ctx, cpu_core_updating_group_time);
  std::set<peerid::PeerID> peers = peer_manager_->ConnectedPeers(ctx);
  {
    ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
    switch (raft_.state) {
      case RAFTSTATE_LOADED_PART_OF_GROUP:
      case RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP:
        peers = raft_.loaded.raft->membership().voting_replicas();
        break;
      case RAFTSTATE_LOADING:
        peers = raft_.loading.mem->voting_replicas();
        break;
      default:
        break;
    }
  }
  auto ts = clock_.GetTime(ctx, peers);
  GAUGE(core, current_groupclock_time)->Set(ts);
  peer_manager_->SetPeerAttestationTimestamp(ctx, ts, raft_config_template_.attestation_timeout());
}

void Core::ConnectToRaftMembers(context::Context* ctx) {
  MEASURE_CPU(ctx, cpu_core_connecting_to_raft_members);
  const auto& membership = raft_.loaded.raft->membership();
  for (auto peer : membership.all_replicas()) {
    if (peer == ID() || peer < ID()) {
      continue;
    }
    auto err = peer_manager_->MaybeConnectToPeer(ctx, peer);
    if (err != error::OK) {
      IDLOG(INFO) << "Requesting connection to detected disconnected peer " << peer << " failed: " << err;
    }
  }
}

raft::ReplicaGroup* Core::NextReplicaGroup(context::Context* ctx) {
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) { return nullptr; }
  raft::Raft* r = raft_.loaded.raft.get();
  if (!r->leader()) { return nullptr; }
  // See if we can add a voting member to increase our total.
  const raft::Membership& m = r->membership();
  auto out = ctx->Protobuf<raft::ReplicaGroup>();
  *out = m.AsProto();
  // Look for an existing replica to promote to voting.
  if (m.voting_replicas().size() < raft_.loaded.group_config.max_voting_replicas() &&
      m.all_replicas().size() > m.voting_replicas().size()) {
    std::string peer_id = "";
    util::Ticks min = util::InvalidTicks;
    for (const auto& peer : m.all_replicas()) {
      util::Ticks last_seen = r->last_seen_ticks(peer);
      if (last_seen < min && m.voting_replicas().count(peer) == 0) {
        peer_id = peer.AsString();
        min = last_seen;
      }
    }
    if (peer_id != "" && min < r->config().election_ticks()) {
      // We've found a peer that's non-voting and that's responded within the last
      // election timeout.  Promote them.
      for (int i = 0; i < out->replicas_size(); i++) {
        if (out->replicas(i).peer_id() == peer_id) {
          out->mutable_replicas(i)->set_voting(true);
          return out;
        }
      }
    }
  }
  // Look for an existing voting replica to demote.
  if (m.voting_replicas().size() > raft_.loaded.group_config.min_voting_replicas()) {
    for (const auto& peer : m.voting_replicas()) {
      util::Ticks last_seen = r->last_seen_ticks(peer);
      if (last_seen != util::InvalidTicks && last_seen > r->config().replica_voting_timeout_ticks()) {
        std::string peer_id = peer.AsString();
        for (int i = 0; i < out->replicas_size(); i++) {
          if (out->replicas(i).peer_id() == peer_id) {
            out->mutable_replicas(i)->set_voting(false);
            return out;
          }
        }
      }
    }
  }
  // Look for non-voting replicas to remove.
  if (m.all_replicas().size() > m.voting_replicas().size()) {
    for (const auto& peer : m.all_replicas()) {
      if (m.voting_replicas().count(peer)) { continue; }
      util::Ticks last_seen = r->last_seen_ticks(peer);
      if (last_seen != util::InvalidTicks && last_seen > r->config().replica_membership_timeout_ticks()) {
        const std::string peer_id = peer.AsString();
        auto it = std::find_if(out->replicas().begin(), out->replicas().end(), [&peer_id](auto& replica) { 
          return replica.peer_id() == peer_id; 
        });
        if (it != out->replicas().end()) {
          out->mutable_replicas()->erase(it);
          return out;
        }
      }
    }
  }
  return nullptr;
}

error::Error Core::HandlePeerMessage(context::Context* ctx, const UntrustedMessage& msg) {
  const auto remote_msg = msg.peer_message();
  // Parsing the peer ID should always succeed, because the peer manager already did it once.
  peerid::PeerID from;
  CHECK(error::OK == from.FromString(remote_msg.peer_id()));
  // If these are created, they will be so within the arena, so they'll
  // be cleaned up when it falls out of scope.
  e2e::EnclaveToEnclaveMessage* decoded = nullptr;
  auto err = peer_manager_->RecvFromPeer(ctx, remote_msg, &decoded);
  if (err != error::OK) {
    LOG(WARNING) << "Failed to receive message from " << from << " of type " << remote_msg.inner_case() << ": " << err;
    return err;
  }
  if (decoded == nullptr) {
    return error::OK;
  }
  return HandleE2E(ctx, from, *decoded);
}

error::Error Core::HandleE2E(context::Context* ctx, const peerid::PeerID& from, const e2e::EnclaveToEnclaveMessage& msg) {
  switch (msg.inner_case()) {
    case e2e::EnclaveToEnclaveMessage::kConnected:
      HandlePeerConnect(ctx, from);
      return error::OK;
    case e2e::EnclaveToEnclaveMessage::kRaftMessage: {
      ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
      MEASURE_CPU(ctx, cpu_core_raft_msg);
      if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP &&
          raft_.state != svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP) {
        return COUNTED_ERROR(Core_RaftState);
      }
      raft_.loaded.raft->Receive(ctx, msg.raft_message(), from);
      RaftStep(ctx);
    } return error::OK;
    case e2e::EnclaveToEnclaveMessage::kTransactionRequest: {
      MEASURE_CPU(ctx, cpu_core_e2e_txn_req);
      return Core::HandleE2ETransaction(ctx, from, msg.transaction_request());
    }
    case e2e::EnclaveToEnclaveMessage::kTransactionResponse: {
      MEASURE_CPU(ctx, cpu_core_e2e_txn_resp);
      const auto& txn_resp = msg.transaction_response();
      ACQUIRE_NAMED_LOCK(lock, e2e_txn_mu_, ctx, lock_core_e2e_txns);
      auto f = outstanding_e2e_transactions_.find(txn_resp.request_id());
      if (f == outstanding_e2e_transactions_.end()) {
        LOG(VERBOSE) << "received response to e2e transaction that has no callback " << txn_resp.request_id();
        return error::OK;
      }
      auto callback = std::move(f->second);
      IDLOG(VERBOSE) << "received response to e2e transaction " << f->first << ": error=" << msg.transaction_response().status();
      outstanding_e2e_transactions_.erase(f);
      timeout_.CancelTimeout(ctx, callback.timeout_cancel);
      lock.unlock();
      callback.callback(ctx, msg.transaction_response().status(), &msg.transaction_response());
    } return error::OK;
    default:
      return error::General_Unimplemented;
  }
}

void Core::HandlePeerConnect(context::Context* ctx, const peerid::PeerID& from) {
  IDLOG(INFO) << "successfully established connection to " << from;

  // On each connect, immediately send our most current (local) timestamp.
  SendTimestamp(ctx, from, clock_.GetLocalTime());

  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  switch (raft_.state) {
    case svr2::RAFTSTATE_LOADING:
      if (!raft_.loading.started) {
        // If we don't have an in-flight request to load stuff and we've connected
        // to a new peer, see if the connection to that new peer is enough to get
        // us started.
        RequestRaftReplication(ctx);
      }
      break;
    case svr2::RAFTSTATE_WAITING_FOR_FIRST_CONNECTION:
      if (from == raft_.waiting_for_first_connection.peer) {
        JoinRaftFromFirstPeer(ctx);
      }
      break;
    case svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP:
    case svr2::RAFTSTATE_LOADED_PART_OF_GROUP:
      raft_.loaded.raft->ResetPeer(ctx, from);
      break;
    default:
      break;
  }
}

error::Error Core::HandleE2ETransaction(context::Context* ctx, const peerid::PeerID& from, const e2e::TransactionRequest& msg) {
  auto e2e_resp = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  auto txn_resp = e2e_resp->mutable_transaction_response();
  txn_resp->set_request_id(msg.request_id());
  error::Error err = error::OK;
  switch (msg.inner_case()) {
    case e2e::TransactionRequest::kPing:
      txn_resp->set_status(error::OK);
      break;
    case e2e::TransactionRequest::kGetRaft: {
      LOG(VERBOSE) << "GetRaft";
      auto out = txn_resp->mutable_get_raft();
      ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
      if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
        err = COUNTED_ERROR(Core_RaftState);
        break;
      }
      *out->mutable_group_config() = raft_.loaded.group_config;
      *out->mutable_replica_group() = raft_.loaded.raft->membership().AsProto();
    } break;
    case e2e::TransactionRequest::kReplicateState:
      // The response to ReplicateStateRequest will be sent async, not within this transaction call.
      return HandleReplicateStateRequest(ctx, from, msg);
    case e2e::TransactionRequest::kReplicateStatePush: {
      err = HandleReplicateStatePush(ctx, msg.replicate_state_push());
    } break;
    case e2e::TransactionRequest::kRaftMembershipRequest: {
      err = HandleRequestRaftMembership(ctx, from, txn_resp);
    } break;
    case e2e::TransactionRequest::kRaftVotingRequest: {
      err = HandleRequestRaftVoting(ctx, from, txn_resp);
    } break;
    case e2e::TransactionRequest::kRaftWrite: {
      err = HandleRaftWrite(ctx, msg.raft_write(), txn_resp);
    } break;
    case e2e::TransactionRequest::kNewTimestampUnixSecs: {
      HandleNewTimestamp(ctx, from, msg.new_timestamp_unix_secs());
    } break;
    case e2e::TransactionRequest::kRaftRemovalRequest:
      // The response to RaftRemovalRequest will be sent async.
      return HandlePeerRequestedRaftRemoval(ctx, from, msg.request_id());
    default:
      LOG(WARNING) << "unknown e2e transaction type " << msg.inner_case();
      err = error::General_Unimplemented;
      break;
  }
  if (err != error::OK || txn_resp->inner_case() == e2e::TransactionResponse::INNER_NOT_SET) {
    return SendE2EError(ctx, from, msg.request_id(), err);
  }
  return peer_manager_->SendToPeer(ctx, from, *e2e_resp);
}

error::Error Core::HandleReplicateStateRequest(context::Context* ctx, const peerid::PeerID& target, const e2e::TransactionRequest& req) {
  const e2e::ReplicateStateRequest& msg = req.replicate_state();
  LOG(VERBOSE) << "HandleReplicateStateRequest";
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    return SendE2EError(ctx, target, req.request_id(), COUNTED_ERROR(Replicate_RaftState));
  }
  if (msg.group_id() != raft_.loaded.raft->group_id()) {
    return SendE2EError(ctx, target, req.request_id(), COUNTED_ERROR(Replicate_GroupMismatch));
  }
  // push_state will live for the duration of this replication.
  auto push_state = std::make_shared<Core::ReplicationPushState>(
      raft_.loaded.raft->log().oldest_stored_idx(), target, req);

  // `target` has requested replication from us, so now we need to ship data
  // down to it.  We do so by sending some number of E2E transactions to `target`,
  // each containing a subset of the data.  Each call to SendNextReplicationState
  // will send one such E2E transaction, wait for it to complete, then send
  // another.  So, by starting multiple here, we allow ourselves to send many
  // at once over the network without waiting for a response from `target`.
  // The multiple requests use (a shared pointer to) a single push_state to
  // coordinate which data has been sent already, which should be sent in the
  // next call to SendNextReplicationState (either here or on a callback to a
  // previous one), coordinating when we're done, and remembering which transaction
  // to complete when we are.
  auto pipeline = enclave_config(ctx)->raft().replication_pipeline();
  for (uint32_t i = 0; i < pipeline && !push_state->finished_sending; i++) {
    SendNextReplicationState(ctx, push_state);
  }
  return error::OK;
}

void Core::SendNextReplicationState(context::Context* ctx, std::shared_ptr<Core::ReplicationPushState> push_state) {
  MEASURE_CPU(ctx, cpu_core_repl_send);
  CHECK(!push_state->finished_sending);
  auto push = ctx->Protobuf<e2e::TransactionRequest>();
  auto out = push->mutable_replicate_state_push();
  out->set_replication_id(push_state->replication_id);
  out->set_replication_sequence(push_state->replication_sequence++);
  out->set_first_log_idx(push_state->logs_from_idx_inclusive);
  size_t size = 0;
  bool at_commit_idx = false;
  auto replication_chunk_bytes = enclave_config(ctx)->raft().replication_chunk_bytes();
  for (auto iter = raft_.loaded.raft->log().At(push_state->logs_from_idx_inclusive); ; iter.Next()) {
    if (!iter.Valid() || iter.Index() > raft_.loaded.db_last_applied_log) {
      LOG(VERBOSE) << "surpassed commit idx " << raft_.loaded.db_last_applied_log;
      at_commit_idx = true;
      break;
    }
    *out->add_entries() = *iter.Entry();
    size += iter.SerializedSize();
    if (size >= replication_chunk_bytes) { break; }
  }

  // our db rows represent the state at `raft_.loaded.db_commit`, so we can
  // only send them if after this message the requester will be at `raft_.loaded.db_commit`
  if (at_commit_idx) {
    size_t rows_to_send =
        (replication_chunk_bytes - out->ByteSizeLong())
        / db_protocol_->MaxRowSerializedSize();
    if (rows_to_send) {  // if we've got space
      auto [row_id, err] = raft_.loaded.db->RowsAsProtos(ctx, push_state->db_from_key_exclusive, rows_to_send, out->mutable_rows());
      if (err != error::OK) {
        LOG(WARNING) << "Error getting rows as protos: " << err;
        if (!push_state->sent_response.exchange(true)) {
          SendE2EError(ctx, push_state->target, push_state->tx, err);
        }
        return;
      }
      push_state->db_from_key_exclusive = row_id;
      if ((size_t) out->rows_size() < rows_to_send) {
        out->set_db_to_end(true);
        push_state->finished_sending = true;
        LOG(INFO) << "Final data being sent";
      }
    }
  }
  *out->mutable_committed_membership() = raft_.loaded.raft->committed_membership().AsProto();
  IDLOG(INFO) << "Replication: sending " << out->entries_size() << " entries (from "
              << push_state->logs_from_idx_inclusive << ") and " << out->rows_size() << " rows to "
              << push_state->target;

  // Update push state based on our output.
  push_state->logs_from_idx_inclusive += out->entries_size();
  bool last_sent_transaction = push_state->finished_sending;
  SendE2ETransaction(ctx, push_state->target, *push, true,
      [this, push_state, last_sent_transaction](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
        if (push_state->sent_response.load()) {
          return;
        } else if (err != error::OK && !push_state->sent_response.exchange(true)) {
          SendE2EError(ctx, push_state->target, push_state->tx, err);
          return;
        }
        ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
        // `last_sent_transaction` will be set if this is the last transaction we send.
        // `push_state->finished_sending` will be set if we've sent that transaction,
        // whether this is it or not.
        if (last_sent_transaction && !push_state->sent_response.exchange(true)) {
          LOG(INFO) << "All replication state pushes complete, returning success for replication";
          SendE2EError(ctx, push_state->target, push_state->tx, error::OK);
        } else if (!push_state->finished_sending) {
          SendNextReplicationState(ctx, push_state);
        }
      });
}

error::Error Core::HandleReplicateStatePush(context::Context* ctx, const e2e::ReplicateStatePush& repl) {
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  MEASURE_CPU(ctx, cpu_core_repl_recv);
  if (raft_.state != svr2::RAFTSTATE_LOADING) { 
    LOG(ERROR) << "Running RequestRaftReplication callback while not loading";
    return COUNTED_ERROR(Core_RaftState);
  }
  if (raft_.loading.log->next_idx() > 1 && repl.first_log_idx() != raft_.loading.log->next_idx()) {
    LOG(ERROR) << "log index mismatch: log.next=" << raft_.loading.log->next_idx()
               << " repl.first=" << repl.first_log_idx();
    return COUNTED_ERROR(Replicate_LogIndexMismatch);
  } else if (!repl.has_committed_membership()) {
    return COUNTED_ERROR(Replicate_MissingCommittedMembership);
  } else if (repl.replication_id() != raft_.loading.replication_id) {
    return COUNTED_ERROR(Replicate_ReplicationID);
  } else if (repl.replication_sequence() != raft_.loading.replication_sequence++) {
    return COUNTED_ERROR(Replicate_ReplicationSequence);
  }
  error::Error err;
  std::tie(raft_.loading.mem, err) = raft::Membership::FromProto(repl.committed_membership());
  RETURN_IF_ERROR(err);
  LOG(INFO) << "received " << repl.entries_size() << " logs starting at " << repl.first_log_idx()
            << " and " << repl.rows_size() << " database rows (have " << raft_.loading.db->row_count() << " rows)";

  raft::Log* log = raft_.loading.log.get();
  // We could be receiving the first set of entries from a replica's truncated set of
  // logs.  In that case, if we were to append the first entry as log index 1, we'd have
  // a mismatch between our log index and theirs.  So, when our log is empty, use their
  // first log index to set what our next index will be.
  if (log->empty()) {
    log->SetNextIdx(repl.first_log_idx());
  }
  // The `ReplicateStateResponse` we are processing contains log entries that have been 
  // committed by the sender and db rows that reflect the state up to the last log sent.
  // This leaves us with three possible scenarios for each log entry we in this response:
  //
  // 1. The log entry affects a row that is also sent in this response. In this case the sender
  //    has already applied this log entry and we MUST NOT apply it again.
  // 2. The log entry affects a row out side the range of rows that has been sent. In this case
  //    the sender will send that row with this log applied in a later message. We MUST NOT
  //    apply this log.
  // 3. The log entry affects a row in the range that had been sent before this request (less
  //    than or equal to the current max key of the loading database). The sender will not 
  //    send this row again and we MUST apply the log.
  // 
  // At this point, before we add the new rows to the loading database, if a log entry has
  // a backup_id greater than the current max key of the loading database then we are 
  // in situation (1) or (2) and MUST NOT apply the log. Otherwise we are in situation (3) and
  // MUST apply the log.
  //
  // `MaybeApplyLogToReplicatingDatabase` will apply logs according to this rule. Once
  // these logs are selectively applied we can add the rows to the loading database.
  for (int i = 0; i < repl.entries_size(); i++) {
    const auto& entry = repl.entries(i);
    // All of our logs are committed logs, so we allow truncation up to the point where
    // we only have our most recent entry in the log.
    RETURN_IF_ERROR(log->Append(entry, log->last_idx()));
    RETURN_IF_ERROR(MaybeApplyLogToReplicatingDatabase(ctx, entry));
  }
  LOG(VERBOSE) << "Now have logs in [" << log->oldest_stored_idx() << ", " << log->last_idx() << "]";
  if (repl.rows_size()) {

    // Ensure that rows are provided in order.  We use a pointer to avoid excess
    // string copies.  By the end of this block, *order will point to the largest
    // backup ID, which we can use to set `lexigraphically_largest_row_loaded_into_db`.
    auto [last, err] = raft_.loading.db->LoadRowsFromProtos(ctx, repl.rows());
    if (last <= raft_.loading.lexigraphically_largest_row_loaded_into_db) {
      return COUNTED_ERROR(Core_ReplicationOutOfOrder);
    }
    raft_.loading.lexigraphically_largest_row_loaded_into_db = last;
  }
  return error::OK;
}

// Apply log entries to the loading database if they are in the database's currently loaded range.
error::Error Core::MaybeApplyLogToReplicatingDatabase(context::Context* ctx, const raft::LogEntry& entry) {
  if (raft_.state != svr2::RAFTSTATE_LOADING ||
      raft_.loading.db.get() == nullptr) {
    return COUNTED_ERROR(Core_RaftState);
  } else if (raft_.loading.lexigraphically_largest_row_loaded_into_db.empty() || entry.data().size() == 0) {
    // We don't want to apply this log to the database, since either we have no rows in the database or this is not a client log.
    return error::OK;
  }
  auto clog = db_protocol_->LogPB(ctx);
  if (!clog->ParseFromString(entry.data())) {
    return COUNTED_ERROR(Core_ReplicatedLogSerialization);
  }
  if (raft_.loading.lexigraphically_largest_row_loaded_into_db < db_protocol_->LogKey(*clog)) {
    return error::OK;
  }
  RETURN_IF_ERROR(db_protocol_->ValidateClientLog(*clog));
  raft_.loading.db->Run(ctx, *clog);
  return error::OK;
}

error::Error Core::HandleRequestRaftMembership(context::Context* ctx, const peerid::PeerID& from, e2e::TransactionResponse* resp) {
  IDLOG(VERBOSE) << "HandleRequestRaftMembership " << from;
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    return COUNTED_ERROR(Core_RaftState);
  }
  std::string peer_string = from.AsString();
  raft::ReplicaGroup g = raft_.loaded.raft->membership().AsProto();
  for (int i = 0; i < g.replicas_size(); i++) {
    if (g.replicas(i).peer_id() == peer_string) {
      return COUNTED_ERROR(Core_DuplicateMembershipPeer);
    }
  }
  g.add_replicas()->set_peer_id(peer_string);
  auto [loc, err] = raft_.loaded.raft->ReplicaGroupChange(ctx, g);
  if (err == error::OK) {
    RaftStep(ctx);
    resp->mutable_raft_membership_response()->MergeFrom(loc);
  }
  return err;
}

error::Error Core::HandleRequestRaftVoting(context::Context* ctx, const peerid::PeerID& from, e2e::TransactionResponse* resp) {
  IDLOG(VERBOSE) << "HandleRequestRaftVoting " << from;
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    return COUNTED_ERROR(Core_RaftState);
  }
  if (raft_.loaded.raft->membership().all_replicas().count(from) != 1) {
    return COUNTED_ERROR(Core_VotingRequestedForNonMember);
  } else if (raft_.loaded.raft->membership().voting_replicas().count(from) != 0) {
    return COUNTED_ERROR(Core_VotingRequestedForVotingMember);
  }

  // This does not respect the max_voting attribute of the RaftConfig.  That's
  // fine, though, because the leader will enforce that before accepting this
  // change.
  raft::ReplicaGroup g = raft_.loaded.raft->membership().AsProto();
  for (int i = 0; i < g.replicas_size(); i++) {
    if (g.replicas(i).peer_id() == from.AsString()) {
      g.mutable_replicas(i)->set_voting(true);
      break;
    }
  }
  auto [loc, err] = raft_.loaded.raft->ReplicaGroupChange(ctx, g);
  if (err == error::OK) {
    RaftStep(ctx);
    resp->mutable_raft_voting_response()->MergeFrom(loc);
  }
  return err;
}

error::Error Core::HandleRaftWrite(context::Context* ctx, const std::string& data, e2e::TransactionResponse* resp) {
  LOG(VERBOSE) << "HandleRaftWrite";
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    return COUNTED_ERROR(Core_RaftState);
  }
  if (raft_.loaded.raft->membership().voting_replicas().size() < raft_.loaded.group_config.min_voting_replicas()) {
    return COUNTED_ERROR(Core_NotEnoughVotingReplicas);
  }
  auto [loc, err] = raft_.loaded.raft->ClientRequest(ctx, data);
  if (err == error::OK) {
    RaftStep(ctx);
    resp->mutable_raft_write()->MergeFrom(loc);
  }
  return err;
}

void Core::HandleNewTimestamp(context::Context* ctx, const peerid::PeerID& from, uint64_t unix_secs) {
  clock_.SetRemoteTime(ctx, from, unix_secs);
  MaybeUpdateGroupTime(ctx);
}

error::Error Core::HandlePeerRequestedRaftRemoval(context::Context* ctx, const peerid::PeerID& from, internal::TransactionID tx) {
  IDLOG(VERBOSE) << "HandlePeerRequestedRaftRemoval " << from;
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    SendE2EError(ctx, from, tx, COUNTED_ERROR(Core_RaftState));
    return error::OK;
  }
  std::string peer_string = from.AsString();
  raft::ReplicaGroup g = raft_.loaded.raft->membership().AsProto();
  raft::ReplicaGroup next = g;
  next.clear_replicas();
  bool found_peer = false;
  for (int i = 0; i < g.replicas_size(); i++) {
    if (g.replicas(i).peer_id() == peer_string) {
      found_peer = true;
    } else {
      *next.add_replicas() = g.replicas(i);
    }
  }
  if (!found_peer) {
    SendE2EError(ctx, from, tx, COUNTED_ERROR(Core_RemoveNonexistentMember));
    return error::OK;
  }
  auto [loc, err] = raft_.loaded.raft->ReplicaGroupChange(ctx, next);
  if (err != error::OK) {
    SendE2EError(ctx, from, tx, err);
    return error::OK;
  }
  peerid::PeerID from_copy = from;
  AddLogTransaction(ctx, loc, [this, f = std::move(from_copy), tx](
      context::Context* ctx,
      error::Error err,
      const raft::LogEntry* entry,
      const db::DB::Response* resp) {
    SendE2EError(ctx, f, tx, err);
  });
  RaftStep(ctx);
  return error::OK;
}

void Core::RaftStep(context::Context* ctx) {
  CHECK(raft_.state == svr2::RAFTSTATE_LOADED_PART_OF_GROUP
      || raft_.state == svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP);
  RaftSendMessages(ctx);
  RaftHandleCommittedLogs(ctx);
}

void Core::RaftSendMessages(context::Context* ctx) {
  // Send out any messages that Raft has for us.
  std::vector<raft::SendableRaftMessage> messages = raft_.loaded.raft->SendableMessages();
  for (size_t i = 0; i < messages.size(); i++) {
    std::set<peerid::PeerID> send_to;
    if (messages[i].to().has_value()) {
      send_to.insert(*messages[i].to());
    } else {
      send_to = raft_.loaded.raft->peers();
    }
    const raft::RaftMessage& raft_msg = messages[i].message();
    for (const auto& peer : send_to) {
      auto e2e_msg = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
      e2e_msg->mutable_raft_message()->MergeFrom(raft_msg);
      error::Error peer_err = peer_manager_->SendToPeer(ctx, peer, *e2e_msg);
      if (peer_err != error::OK) {
        // If we've failed here, our peer is probably in a DISCONNECTED state.
        // This will be handled eventually by having the peers reset themselves,
        // at which point we'll get a new `connected` e2e message, which will
        // call Raft's ResetPeer() and restart sends of messages to this peer.
        LOG(WARNING) << "failed to generate peer raft message to " << peer << ": " << peer_err;
        continue;
      }
    }
  }
}

void Core::AddLogTransaction(context::Context* ctx, const raft::LogLocation& loc, LogTransactionCallback cb) {
  ACQUIRE_LOCK(outstanding_log_transactions_mu_, ctx, lock_core_log_txns);
  LogTransaction log_tx = {
    .term = loc.term(),
    .cb = cb,
    .expected_hash_chain = loc.hash_chain(),
  };
  outstanding_log_transactions_.emplace(loc.idx(), std::move(log_tx));
}

Core::LogTransactionCallback Core::ClientLogTransaction(context::Context* ctx, client::ClientID client_id, internal::TransactionID tx) {
  // Record information about this ClientLog message so we can respond to the client later.
  return [this, client_id, tx](
      context::Context* ctx,
      error::Error err,
      const raft::LogEntry* entry,
      const db::DB::Response* response) {
    if (err == error::Core_LogTransactionCancelled) {
      COUNTER(core, client_transaction_cancelled)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - cancelled";
      ReplyWithError(ctx, tx, COUNTED_ERROR(Client_TransactionCancelled));
      client_manager_->RemoveClient(ctx, client_id);
    } else if (err != error::OK) {
      COUNTER(core, client_transaction_error)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - error";
      ReplyWithError(ctx, tx, err);
      client_manager_->RemoveClient(ctx, client_id);
    } else if (response == nullptr) {
      COUNTER(core, client_transaction_invalid)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - invalid";
      ReplyWithError(ctx, tx, COUNTED_ERROR(Client_TransactionInvalid));
      client_manager_->RemoveClient(ctx, client_id);
    } else if (
        client::Client* client = client_manager_->GetClient(ctx, client_id);
        client == nullptr) {
      COUNTER(core, client_transaction_dne)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - does_not_exist";
      ReplyWithError(ctx, tx, COUNTED_ERROR(Client_AlreadyClosed));
      client_manager_->RemoveClient(ctx, client_id);
    } else if (
        auto [ciphertext, encrypt_err] = client->EncryptResponse(ctx, *response);
        encrypt_err != error::OK) {
      COUNTER(core, client_transaction_encrypterr)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - encrypt_fail:" << encrypt_err;
      ReplyWithError(ctx, tx, encrypt_err);
      client_manager_->RemoveClient(ctx, client_id);
    } else {
      COUNTER(core, client_transaction_success)->Increment();
      LOG(VERBOSE) << "- client " << client_id << " - success";
      auto enclave_msg = ctx->Protobuf<EnclaveMessage>();
      auto resp = enclave_msg->mutable_h2e_response();
      resp->set_request_id(tx);
      auto existing_client = resp->mutable_existing_client_reply();
      *existing_client->mutable_data() = std::move(ciphertext);
      sender::Send(ctx, *enclave_msg);
    }
  };
}

error::Error Core::RaftWriteLogTransaction(context::Context* ctx, const std::string& data, Core::LogTransactionCallback cb) {
  ACQUIRE_LOCK(raft_.mu, ctx, lock_core_raft);
  if (raft_.state != svr2::RAFTSTATE_LOADED_PART_OF_GROUP) {
    return COUNTED_ERROR(Core_RaftState);
  }
  if (raft_.loaded.raft->is_leader()) {
    if (raft_.loaded.raft->membership().voting_replicas().size() < raft_.loaded.group_config.min_voting_replicas()) {
      return COUNTED_ERROR(Core_NotEnoughVotingReplicas);
    }
    // Add the ClientLog message to the Raft log
    auto [loc, raft_err] = raft_.loaded.raft->ClientRequest(ctx, data);
    if (raft_err != error::OK) {
      return raft_err;
    }
    AddLogTransaction(ctx, loc, cb);
    RaftStep(ctx);
  } else if (raft_.loaded.raft->leader().has_value()) {
    // Forward this ClientLog to the leader to be added to the log
    auto txn = ctx->Protobuf<e2e::TransactionRequest>();
    txn->set_raft_write(data);
    SendE2ETransaction(ctx, *raft_.loaded.raft->leader(), *txn, true,
        [this, cb](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
          if (err == error::OK && resp->inner_case() == e2e::TransactionResponse::kStatus) {
            err = resp->status();
          }
          if (err != error::OK) {
            cb(ctx, err, nullptr, nullptr);
            return;
          }
          // Record information about this ClientLog message so we can respond to the client later.
          // This replica is responsible for responding to the client (and is the only replica with 
          // the Noise state that is needed to do that).
          if (resp->inner_case() != e2e::TransactionResponse::kRaftWrite) {
            cb(ctx, COUNTED_ERROR(Core_IncorrectE2EResponseType), nullptr, nullptr);
            return;
          }
          AddLogTransaction(ctx, resp->raft_write(), cb);
        });
  } else {
    return COUNTED_ERROR(Core_LeaderUnknown);
  }
  return error::OK;
}

void Core::SendTimestamp(context::Context* ctx, peerid::PeerID to, uint64_t unix_secs) {
  auto req = ctx->Protobuf<e2e::TransactionRequest>();
  req->set_new_timestamp_unix_secs(unix_secs);
  SendE2ETransaction(
      ctx, to, *req, true,
      [unix_secs, to](context::Context* ctx, error::Error err, const e2e::TransactionResponse* resp) {
        // Ignore, but log error.
        if (err != error::OK) {
          LOG(INFO) << "Failed to send timestamp (" << unix_secs << ") to " << to << ": " << err;
        }
      });
}

void Core::SendTimestampToAll(context::Context* ctx) {
  auto peers = peer_manager_->ConnectedPeers(ctx);
  for (auto peer : peers) {
    SendTimestamp(ctx, std::move(peer), clock_.GetLocalTime());
  }
  util::Ticks next = std::max(1U, enclave_config(ctx)->send_timestamp_ticks());
  timeout_.SetTimeout(ctx, next, [this](context::Context* ctx) {
    SendTimestampToAll(ctx);
  });
}

error::Error Core::SendE2EError(context::Context* ctx, const peerid::PeerID& from, internal::TransactionID id, error::Error err) {
  auto e2e = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  auto out = e2e->mutable_transaction_response();
  out->set_request_id(id);
  out->set_status(err);
  if (out->status() != error::OK) {
    IDLOG(VERBOSE) << "request " << id << " from " << from << " error: " << err;
  }
  return peer_manager_->SendToPeer(ctx, from, *e2e);
}

void Core::RaftHandleCommittedLogs(context::Context* ctx) {
  // See if Raft has any committed logs for us.
  MEASURE_CPU(ctx, cpu_core_committed_logs);
  while (true) {
    auto [idx, entry] = raft_.loaded.raft->TakeCommittedLog();
    if (idx == 0) {
      // There's no additional logs, we're done!
      return;
    }
    raft_.loaded.db_last_applied_log = idx;
    LOG(VERBOSE) << "at db_last_applied_log " << idx;
    GAUGE(core, last_index_applied_to_db)->Set(idx);
    if (entry.has_membership_change()) {
      HandleRaftMembershipChange(ctx, idx, entry.term(), entry.membership_change());
    }
    db::DB::Response* response = RaftApplyLogToDatabase(ctx, idx, entry);
    // Unless this log contained a valid client transaction,
    // [response] will be null at this point.
    HandleLogTransactionsForRaftLog(ctx, idx, entry, response);
    COUNTER(core, raft_log_applied)->Increment();
  }
}

void Core::HandleRaftMembershipChange(
    context::Context* ctx,
    raft::LogIdx idx,
    raft::TermId term,
    const raft::ReplicaGroup& membership_change) {
  switch (raft_.state) {
    case svr2::RAFTSTATE_LOADED_PART_OF_GROUP: {
      if (!ContainsMe(raft_.loaded.raft->me(), membership_change)) {
        LOG(WARNING) << "I've been removed from Raft at index " << idx;
        raft_.state = svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP;
        ACQUIRE_LOCK(outstanding_log_transactions_mu_, ctx, lock_core_log_txns);
        for (auto iter = outstanding_log_transactions_.begin();
            iter != outstanding_log_transactions_.end();
            iter = outstanding_log_transactions_.erase(iter)) {
          const auto& log_tx = iter->second;
          log_tx.cb(ctx, COUNTED_ERROR(Core_RemovedFromRaft), nullptr, nullptr);
        }
      }
    } break;
    case svr2::RAFTSTATE_LOADED_REQUESTING_MEMBERSHIP: {
      if (ContainsMe(raft_.loaded.raft->me(), membership_change)) {
        LOG(INFO) << "I've been added to Raft at index " << idx;
        raft_.state = svr2::RAFTSTATE_LOADED_PART_OF_GROUP;
      }
    } break;
    default:
      CHECK(nullptr == "in HandleRaftMembershipChange but not part of group or requesting membership");
      break;
  }
}

db::DB::Response* Core::RaftApplyLogToDatabase(
    context::Context* ctx,
    raft::LogIdx idx,
    const raft::LogEntry& committed_entry) {
  if (committed_entry.data().size() == 0) {
    // This is an internal-to-Raft log, we don't need to care.
    // These are generated on leader election, and will eventually
    // be used for membership changes as well.
    return nullptr;
  }
  auto client_log = db_protocol_->LogPB(ctx);
  if (!client_log->ParseFromString(committed_entry.data())) {
    LOG(ERROR) << "raft log message does not parse: " << idx;
    return nullptr;
  }
  error::Error validate_err = db_protocol_->ValidateClientLog(*client_log);
  if (validate_err != error::OK) {
    LOG(ERROR) << "raft log message invalid: " << idx << " - " << validate_err;
    return nullptr;
  }
  return raft_.loaded.db->Run(ctx, *client_log);
}

void Core::HandleLogTransactionsForRaftLog(context::Context* ctx, raft::LogIdx idx, const raft::LogEntry& entry, const db::DB::Response* response) {
  // See if this is a log we should handle.
  const char* type =
      entry.data().size() == 0
      ? "raft_internal"
      : response != nullptr
          ? "valid_client"
          : "invalid";
  LOG(VERBOSE) << "raft log " << idx << " at term " << entry.term() << " - " << type;;
  ACQUIRE_LOCK(outstanding_log_transactions_mu_, ctx, lock_core_log_txns);
  auto [iter, upper] = outstanding_log_transactions_.equal_range(idx);
  for (; iter != upper; iter = outstanding_log_transactions_.erase(iter)) {
    const LogTransaction& log_tx = iter->second;
    if (log_tx.term != entry.term()) {
      COUNTER(core, log_transactions_cancelled)->Increment();
      log_tx.cb(ctx, COUNTED_ERROR(Core_LogTransactionCancelled), nullptr, nullptr);
    } else if (log_tx.expected_hash_chain.size() > 0 // ignore hash chain if length is 0
               && !util::ConstantTimeEquals(log_tx.expected_hash_chain, entry.hash_chain())) {
      log_tx.cb(ctx, COUNTED_ERROR(Core_InvalidLogTransactionHashChain), nullptr, nullptr);
    } else {
      COUNTER(core, log_transactions_success)->Increment();
      log_tx.cb(ctx, error::OK, &entry, response);
    }
  }
}

void Core::SendE2ETransaction(
    context::Context* ctx,
    const peerid::PeerID& to,
    const e2e::TransactionRequest& req,
    bool with_timeout,
    E2ECallback callback) {
  ACQUIRE_NAMED_LOCK(lock, e2e_txn_mu_, ctx, lock_core_e2e_txns);
  internal::TransactionID tx = ++e2e_txn_id_;
  auto e2e = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  e2e->mutable_transaction_request()->MergeFrom(req);
  e2e->mutable_transaction_request()->set_request_id(tx);
  error::Error err = peer_manager_->SendToPeer(ctx, to, *e2e);
  if (err != error::OK) {
    IDLOG(DEBUG) << "failed to start transaction " << tx << " to " << to << ": " << err;
    lock.unlock();
    // This is a problematic codepath right now, as we call the callback inline.
    // Sometimes, the callback has to acquire a lock that's already acquired
    // by SendE2ETransaction's caller.  The optimal approach would be to defer
    // this callback to some time when the caller has returned.
    callback(ctx, err, nullptr);
    return;
  }
  IDLOG(DEBUG) << "successfully started transaction " << tx << " to " << to;
  timeout::Cancel tc;
  if (with_timeout) {
    tc = timeout_.SetTimeout(ctx, enclave_config(ctx)->e2e_txn_timeout_ticks(),
        [this, tx, to](context::Context* ctx) {
          ACQUIRE_NAMED_LOCK(lock, e2e_txn_mu_, ctx, lock_core_e2e_txns);
          auto f = outstanding_e2e_transactions_.find(tx);
          if (f == outstanding_e2e_transactions_.end()) return;
          IDLOG(DEBUG) << "e2e transaction " << tx << " to " << to << " timed out";
          E2ECallback cb = std::move(f->second.callback);
          outstanding_e2e_transactions_.erase(f);
          lock.unlock();
          cb(ctx, error::Core_E2ETransactionTimeout, nullptr);
        });
  }
  outstanding_e2e_transactions_[tx] = {
    .callback = callback,
    .timeout_cancel = tc,
  };
}

}  // namespace svr2::core

