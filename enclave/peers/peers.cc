// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sstream>
#include <iomanip>
#include <functional>

#include <noise/protocol/constants.h>
#include <noise/protocol/errors.h>

#include "peers/peers.h"
#include "util/macros.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "env/env.h"
#include "sip/halfsiphash.h"
#include "util/endian.h"
#include "util/log.h"
#include "util/constant.h"
#include "sender/sender.h"
#include "metrics/metrics.h"

// There's some mildly complicated locking going on between Peer and PeerManager
// objects to maintain the necessary invariants for smooth operation.
// In a multi-threaded environment, we want encryption/decryption operations to
// be able to utilize multiple cores.  However, peer connections are by their
// nature serial, as each connection uses a serialized set of noise state for
// {en,de}cryption purposes.  We've striven to make this locking as simple as
// possible, and we've come up with this:
//
// * The peer manager's lock protects its map (peers_) of peers.  Peer objects
//   may be added to this list, but are never removed.  This is because...
// * Each Peer object contains a lock of its own, which serializes communication
//   across that peer's established connection.
//
// In short, the PeerManager lock is simply for lookup, while the Peer lock
// is used for all encryption/decryption/etc. associated with a peer.  This
// means that each peer/peer connection is effectively single-threaded, but
// if multiple messages are received from multiple peers, the enclave can
// process their encryption in parallel.

namespace svr2::peers {

static NoiseProtocolId peer_to_peer_protocol = {
    .prefix_id = NOISE_PREFIX_STANDARD,
    .pattern_id = NOISE_PATTERN_KK,
    .dh_id = NOISE_DH_CURVE25519,
    // We use ChaChaPoly for client communication, because it's easier on clients
    // and the vast majority of client interaction is dominated by the DH key exchange,
    // rather than the actual stream cipher.  However, for peer-to-peer communication,
    // we establish connections infrequently and then use the stream cipher a LOT.
    // This is especially true during initial replication, when the entire database
    // state needs to be encrypted/decrypted.  Since we use a libsodium backend, we
    // have access to hardware-accelerated AES, so we use that.
    .cipher_id = NOISE_CIPHER_AESGCM,
    .hash_id = NOISE_HASH_SHA256,
    .hybrid_id = 0,
};

Peer::Peer(const peerid::PeerID& id, PeerManager* parent)
    : id_(id),
      handshake_(noise::WrapHandshakeState(nullptr)),
      tx_(noise::WrapCipherState(nullptr)),
      tx_rekey_(0),
      rx_(noise::WrapCipherState(nullptr)),
      rx_rekey_(0),
      parent_(parent),
      last_attestation_(0) {}

error::Error Peer::Send(
    context::Context* ctx,
    const e2e::EnclaveToEnclaveMessage& msg) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  MEASURE_CPU(ctx, cpu_peer_encrypt);
  if (InternalCurrentState() != PEER_CONNECTED) {
    return COUNTED_ERROR(Peers_SendBeforeConnect);
  }
  auto enclave_message = ctx->Protobuf<EnclaveMessage>();
  auto send = enclave_message->mutable_peer_message();
  std::string serialized;
  if (!msg.SerializeToString(&serialized)) {
    return COUNTED_ERROR(Peers_EncryptSerialize);
  }
  auto [ciphertext, err] = noise::Encrypt(tx_.get(), serialized);
  if (err != error::OK) {
    // An encryption error probably means bad noise state, which is unrecoverable.
    InternalDisconnect();
    SendRst(ctx, id_);
    return err;
  }
  if (++tx_rekey_ == 0) {
    noise_cipherstate_rekey(tx_.get());
  }
  send->mutable_data()->swap(ciphertext);
  id_.ToString(send->mutable_peer_id());
  sender::Send(ctx, *enclave_message);
  return error::OK;
}

error::Error Peer::Recv(
    context::Context* ctx,
    const PeerMessage& msg,
    e2e::EnclaveToEnclaveMessage** decoded) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  switch (msg.inner_case()) {
    case PeerMessage::kSynack: {
      MEASURE_CPU(ctx, cpu_peer_connect2);
      if (InternalCurrentState() != PEER_CONNECTING) {
        InternalDisconnect();
        SendRst(ctx, id_);
        return COUNTED_ERROR(Peers_SynAckNotConnecting);
      }
      error::Error err = FinishConnection(ctx, msg.synack(), decoded);
      if (err != error::OK) {
        InternalDisconnect();
        SendRst(ctx, id_);
        return err;
      }
    } return error::OK;
    case PeerMessage::kData: {
      MEASURE_CPU(ctx, cpu_peer_decrypt);
      if (InternalCurrentState() != PEER_CONNECTED) {
        return COUNTED_ERROR(Peers_DataNotConnected);
      }
      auto [plaintext, err] = noise::Decrypt(rx_.get(), msg.data());
      if (err != error::OK) {
        // A decryption error probably means bad noise state, which is unrecoverable.
        InternalDisconnect();
        SendRst(ctx, id_);
        return err;
      }
      if (++rx_rekey_ == 0) {
        noise_cipherstate_rekey(rx_.get());
      }
      auto e2e_message = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
      if (!e2e_message->ParseFromString(plaintext)) {
        return COUNTED_ERROR(Peers_DecryptParse);
      }
      if (e2e_message->inner_case() == e2e::EnclaveToEnclaveMessage::kAttestationUpdate) {
        auto err = CheckNextAttestation(ctx, e2e_message->attestation_update());
        if (err != error::OK) {
          LOG(WARNING) << "Peer " << id_ << " attestation update failure: " << err;
          InternalDisconnect();
          SendRst(ctx, id_);
        }
        return err;
      }
      *decoded = e2e_message;
    } return error::OK;
    case PeerMessage::kRst:
      LOG(INFO) << "Received RST from " << id_;
      InternalDisconnect();
      return error::OK;
    case PeerMessage::kSyn:
      CHECK(nullptr == "PeerManager.RecvFromPeer should have called Accept, not Recv");
    default:
      return COUNTED_ERROR(Peers_InvalidMsg);
  }
}

error::Error Peer::FinishConnection(
    context::Context* ctx,
    const std::string& synack,
    e2e::EnclaveToEnclaveMessage** decoded) {
  if (NOISE_ACTION_READ_MESSAGE != noise_handshakestate_get_action(handshake_.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }

  noise::HandshakeState local_handshake = noise::WrapHandshakeState(nullptr);
  local_handshake.swap(handshake_);

  e2e::ConnectRequest* conn = ctx->Protobuf<e2e::ConnectRequest>();
  if (!conn->ParseFromString(synack)) {
    return COUNTED_ERROR(Peers_FinishParseHandshake);
  }
  auto remote_attestation = conn->attestation();
  auto ts = parent_->CurrentTime();
  auto [att, att_err] = env::environment->Attest(ctx, ts, remote_attestation);
  RETURN_IF_ERROR(att_err);
  auto [key, key_err] = util::StringToByteArray<32>(att.public_key());
  RETURN_IF_ERROR(key_err);
  if (!util::ConstantTimeEquals(key, this->ID().Get())) {
    return error::Peers_FinishIDMismatch; 
  }
  RETURN_IF_ERROR(parent_->Minimums().CheckValues(ctx, att.minimum_values()));

  NoiseBuffer buf = noise::BufferInputFromString(conn->mutable_handshake());
  if (NOISE_ERROR_NONE != noise_handshakestate_read_message(local_handshake.get(), &buf, nullptr)) {
    return COUNTED_ERROR(Peers_FinishReadHandshake);
  }
  if (NOISE_ACTION_SPLIT != noise_handshakestate_get_action(local_handshake.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }
  NoiseCipherState* tx;
  NoiseCipherState* rx;
  if (NOISE_ERROR_NONE != noise_handshakestate_split(local_handshake.get(), &tx, &rx)) {
    return COUNTED_ERROR(Peers_FinishSplit);
  }

  minimums_ = att.minimum_values();
  tx_.reset(tx);
  rx_.reset(rx);
  tx_rekey_ = 0;
  rx_rekey_ = 0;
  auto e2e_message = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  e2e_message->set_connected(true);
  *decoded = e2e_message;
  last_attestation_ = ts;
  return error::OK;
}

error::Error Peer::Connect(
    context::Context* ctx,
    const noise::DHState& priv,
    const e2e::Attestation& attestation) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  return Peer::InternalConnect(ctx, priv, attestation);
}

std::pair<bool, error::Error> Peer::MaybeConnect(
    context::Context* ctx,
    const noise::DHState& priv,
    const e2e::Attestation& attestation) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  switch (InternalCurrentState()) {
    case PEER_CONNECTING:
    case PEER_CONNECTED:
      return std::make_pair(false, error::OK);
    case PEER_DISCONNECTED:
    default:
      return std::make_pair(true, InternalConnect(ctx, priv, attestation));
  }
}

error::Error Peer::InternalConnect(
    context::Context* ctx,
    const noise::DHState& priv,
    const e2e::Attestation& attestation) {
  MEASURE_CPU(ctx, cpu_peer_connect);
  RETURN_IF_ERROR(Reset(priv, NOISE_ROLE_INITIATOR));
  CHECK(handshake_.get());

  // Take away our class state for the duration of this call, so that if something goes
  // wrong we don't have a misbehaving handshake lying around.
  noise::HandshakeState local_handshake = noise::WrapHandshakeState(nullptr);
  local_handshake.swap(handshake_);
  if (NOISE_ACTION_WRITE_MESSAGE != noise_handshakestate_get_action(local_handshake.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }

  e2e::ConnectRequest* conn = ctx->Protobuf<e2e::ConnectRequest>();
  conn->mutable_attestation()->CopyFrom(attestation);

  // Create the initial Noise initiator handshake request buffer in [conn->handshake].
  conn->mutable_handshake()->resize(noise::HANDSHAKE_INIT_SIZE, '\0');
  NoiseBuffer buf;
  noise_buffer_set_output(
      buf,
      reinterpret_cast<uint8_t*>(const_cast<char*>(conn->mutable_handshake()->data())),
      conn->mutable_handshake()->size());
  if (NOISE_ERROR_NONE != noise_handshakestate_write_message(local_handshake.get(), &buf, nullptr)) {
    return COUNTED_ERROR(Peers_ConnectWriteHandshake);
  }
  conn->mutable_handshake()->resize(buf.size);

  // Create the [encoded] output message by serializing [conn].
  auto enclave_message = ctx->Protobuf<EnclaveMessage>();
  auto send = enclave_message->mutable_peer_message();
  id_.ToString(send->mutable_peer_id());
  if (!conn->SerializeToString(send->mutable_syn())) {
    return COUNTED_ERROR(Peers_ConnectSerializeHandshake);
  }

  // Give back the (well-behaved) handshake state.
  local_handshake.swap(handshake_);

  sender::Send(ctx, *enclave_message);
  return error::OK;
}

error::Error Peer::Accept(
    context::Context* ctx,
    const noise::DHState& priv,
    const e2e::Attestation& attestation,
    const std::string& syn,
    e2e::EnclaveToEnclaveMessage** decoded) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  MEASURE_CPU(ctx, cpu_peer_accept);
  RETURN_IF_ERROR(Reset(priv, NOISE_ROLE_RESPONDER));
  CHECK(handshake_.get());

  // Take away our class state for the duration of this call, so that if something goes
  // wrong we don't have a misbehaving handshake lying around.
  noise::HandshakeState local_handshake = noise::WrapHandshakeState(nullptr);
  local_handshake.swap(handshake_);

  if (NOISE_ACTION_READ_MESSAGE != noise_handshakestate_get_action(local_handshake.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }

  e2e::ConnectRequest* conn_request = ctx->Protobuf<e2e::ConnectRequest>();
  if (!conn_request->ParseFromString(syn)) {
    return COUNTED_ERROR(Peers_AcceptParseHandshake);
  }

  // validate the attestation
  auto remote_attestation = conn_request->attestation();
  auto ts = parent_->CurrentTime();
  auto [att, att_err] = env::environment->Attest(ctx, ts, remote_attestation);
  if(att_err != error::OK) {
    return att_err;
  }
  if(!util::ConstantTimeEquals(att.public_key(), this->ID().Get())) {
    LOG(ERROR) << "ID mismatch with peer, want " << this->ID() << ", have " << util::ToHex(att.public_key());
    return error::Peers_AcceptIDMismatch; 
  }
  RETURN_IF_ERROR(parent_->Minimums().CheckValues(ctx, att.minimum_values()));

  NoiseBuffer read_buf = noise::BufferInputFromString(conn_request->mutable_handshake());
  int err = 0;
  if (NOISE_ERROR_NONE != (err = noise_handshakestate_read_message(local_handshake.get(), &read_buf, nullptr))) {
    return COUNTED_ERROR(Peers_AcceptReadHandshake);
  }
  if (NOISE_ACTION_WRITE_MESSAGE != noise_handshakestate_get_action(local_handshake.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }
  auto conn_response = ctx->Protobuf<e2e::ConnectRequest>();
  conn_response->mutable_attestation()->CopyFrom(attestation);
  conn_response->mutable_handshake()->resize(noise::HANDSHAKE_INIT_SIZE, '\0');
  NoiseBuffer write_buf = noise::BufferOutputFromString(conn_response->mutable_handshake());
  if (NOISE_ERROR_NONE != noise_handshakestate_write_message(local_handshake.get(), &write_buf, nullptr)) {
    return COUNTED_ERROR(Peers_AcceptWriteHandshake);
  }
  conn_response->mutable_handshake()->resize(write_buf.size, 0);
  auto enclave_message = ctx->Protobuf<EnclaveMessage>();
  auto send = enclave_message->mutable_peer_message();
  id_.ToString(send->mutable_peer_id());
  if (!conn_response->SerializeToString(send->mutable_synack())) {
    return COUNTED_ERROR(Peers_AcceptSerializeHandshake);
  }
  if (NOISE_ACTION_SPLIT != noise_handshakestate_get_action(local_handshake.get())) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }

  NoiseCipherState* tx;
  NoiseCipherState* rx;
  if (NOISE_ERROR_NONE != noise_handshakestate_split(local_handshake.get(), &tx, &rx)) {
    return COUNTED_ERROR(Peers_AcceptSplit);
  }
  minimums_ = att.minimum_values();
  tx_.reset(tx);
  rx_.reset(rx);
  tx_rekey_ = 0;
  rx_rekey_ = 0;

  auto e2e_message = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  e2e_message->set_connected(true);
  *decoded = e2e_message;
  last_attestation_ = ts;
  sender::Send(ctx, *enclave_message);
  return error::OK;
}

void Peer::Disconnect(context::Context* ctx) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  InternalDisconnect();
  Peer::SendRst(ctx, id_);
}

PeerState Peer::CurrentState(context::Context* ctx) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  return InternalCurrentState();
}

PeerState Peer::InternalCurrentState() const {
  if (handshake_.get() != nullptr) {
    return PEER_CONNECTING;
  }
  if (tx_.get() != nullptr && rx_.get() != nullptr) {
    return PEER_CONNECTED;
  }
  return PEER_DISCONNECTED;
}

void Peer::InternalDisconnect() {
  handshake_.reset(nullptr);
  tx_.reset(nullptr);
  rx_.reset(nullptr);
  tx_rekey_ = 0;
  rx_rekey_ = 0;
  last_attestation_ = 0;
  minimums_.Clear();
}

void Peer::SendRst(context::Context* ctx, const peerid::PeerID& id) {
  auto enclave_message = ctx->Protobuf<EnclaveMessage>();
  auto send = enclave_message->mutable_peer_message();
  id.ToString(send->mutable_peer_id());
  send->set_rst(true);
  sender::Send(ctx, *enclave_message);
}

error::Error Peer::Reset(const noise::DHState& priv, int noise_role) {
  InternalDisconnect();
  NoiseHandshakeState* hsp;
  if (NOISE_ERROR_NONE != noise_handshakestate_new_by_id(&hsp, &peer_to_peer_protocol, noise_role)) {
    return COUNTED_ERROR(Peers_HandshakeState);
  }
  noise::HandshakeState hs = noise::WrapHandshakeState(hsp);

  if (NOISE_ERROR_NONE != noise_dhstate_copy(
      noise_handshakestate_get_local_keypair_dh(hsp),
      priv.get())) {
    return COUNTED_ERROR(Peers_CopyDHState);
  }
  if (NOISE_ERROR_NONE != noise_dhstate_set_public_key(
      noise_handshakestate_get_remote_public_key_dh(hsp),
      id_.Get().data(),
      id_.Get().size())) {
    return COUNTED_ERROR(Peers_SetRemotePublicKey);
  }
  if (NOISE_ERROR_NONE != noise_handshakestate_start(hsp)) {
    return COUNTED_ERROR(Peers_HandshakeStart);
  }

  handshake_.swap(hs);
  return error::OK;
}

error::Error Peer::CheckNextAttestation(context::Context* ctx, const e2e::Attestation& a) {
  auto now = parent_->CurrentTime();
  auto [att, err] = env::environment->Attest(ctx, now, a);
  RETURN_IF_ERROR(err);
  if (!util::ConstantTimeEquals(att.public_key(), id_.Get())) {
    LOG(ERROR) << "Peer " << id_ << " sent attestation with incorrect key";
    return COUNTED_ERROR(Peers_AttestationKeyChanged);
  }
  LOG(DEBUG) << "Peer " << id_ << " re-attested at " << now;
  last_attestation_ = now;
  minimums_ = att.minimum_values();
  return error::OK;
}

void Peer::MaybeDisconnectIfAttestationTooOld(context::Context* ctx, util::UnixSecs now, util::UnixSecs attestation_timeout) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  auto state = InternalCurrentState();
  if (// If we're already disconnected ...
      state == PEER_DISCONNECTED ||
      // ... or our attestation timestamp is in a good range ...
      (now <= last_attestation_ + attestation_timeout && now >= last_attestation_ - attestation_timeout) ||
      // ... or we're connecting and we haven't yet received a synack with an attestation ...
      (state == PEER_CONNECTING && last_attestation_ == 0)) {
    // ... then there's no need for us to disconnect due to attestation timestamp.
    return;
  }
  LOG(WARNING) << "Attestation for " << id_ << " too old (ts=" << last_attestation_ << ", now=" << now << "), disconnecting";
  InternalDisconnect();
  SendRst(ctx, id_);
}

void Peer::PopulateConnectionStatus(context::Context* ctx, ConnectionStatus* status) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  status->set_state(InternalCurrentState());
  status->set_last_attestation_unix_secs(last_attestation_);
}

error::Error Peer::CheckMinimums(context::Context* ctx, const minimums::Minimums& minimums) {
  ACQUIRE_LOCK(mu_, ctx, lock_peer);
  // A peer that isn't fully connected we consider successful, since its transition to
  // connected will re-check minimums.
  if (InternalCurrentState() != PEER_CONNECTED) { return error::OK; }
  return minimums.CheckValues(ctx, minimums_);
}

PeerManager::PeerManager(minimums::Minimums* mins)
    : dhstate_(noise::WrapDHState(nullptr)),
      init_success_(false),
      time_(0),
      minimums_(mins) {}
PeerManager::~PeerManager() {}

PeerState PeerManager::PeerState(context::Context* ctx, const peerid::PeerID& id) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  auto finder = peers_.find(id);
  if (finder == peers_.end()) {
    return PEER_DISCONNECTED;
  }
  return finder->second->CurrentState(ctx);
}

error::Error PeerManager::Init(context::Context* ctx) {
  NoiseDHState* dhstate;
  if (NOISE_ERROR_NONE != noise_dhstate_new_by_id(&dhstate, peer_to_peer_protocol.dh_id)) {
    return COUNTED_ERROR(Peers_NewKey);
  }
  noise::DHState dh = noise::WrapDHState(dhstate);
  if (NOISE_ERROR_NONE != noise_dhstate_generate_keypair(dhstate)) {
    return COUNTED_ERROR(Peers_NewKeyGenerate);
  }
  env::PublicKey public_key{};
  if (NOISE_ERROR_NONE != noise_dhstate_get_public_key(dhstate, public_key.data(), sizeof(public_key))) {
    return COUNTED_ERROR(Peers_NewKeyPublic);
  }

  attestation::AttestationData data;
  *data.mutable_public_key() = util::ByteArrayToString(public_key);
  // It's assumed that env->Evidence will fill in data.minimums.
  auto [evidence_and_endorsements, err] = env::environment->Evidence(ctx, data);
  RETURN_IF_ERROR(err);

  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  if (init_success_.exchange(true)) {
    return COUNTED_ERROR(Peers_ReInit);
  }
  dhstate_.swap(dh);
  id_ = peerid::PeerID(public_key.data());
  most_recent_attestation_.CopyFrom(evidence_and_endorsements);
  return error::OK;
}

static peerid::PeerID invalid_id;

const peerid::PeerID& PeerManager::ID() const {
  if (!init_success_.load()) { return invalid_id; }
  return id_;
}

error::Error PeerManager::RefreshAttestation(context::Context* ctx) {
  attestation::AttestationData att;
  *att.mutable_public_key() = util::ByteArrayToString(ID().Get());
  // It's assumed that env->Evidence will fill in data.minimums.
  auto [evidence_and_endorsements, err] = env::environment->Evidence(ctx, att);
  if (err != error::OK) {
    COUNTER(peers, attestation_refresh_failure)->Increment();
    return err;
  }

  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  COUNTER(peers, attestation_refresh_success)->Increment();
  most_recent_attestation_ = evidence_and_endorsements;
  auto msg = ctx->Protobuf<e2e::EnclaveToEnclaveMessage>();
  *msg->mutable_attestation_update() = most_recent_attestation_;

  LOG(DEBUG) << "Sending refreshed attestation to peers";
  for (auto iter = peers_.begin(); iter != peers_.end(); ++iter) {
    if (iter->second->CurrentState(ctx) == PEER_CONNECTED) {
      auto err = iter->second->Send(ctx, *msg);
      LOG(VERBOSE) << "Sent refreshed attestation to " << iter->first << ": " << err;
      if (err != error::OK) {
        LOG(WARNING) << "Sending most recent attestation to " << iter->first << " failed: " << err;
      }
    }
  }
  return error::OK;
}

Peer* PeerManager::CreatePeer(context::Context* ctx, const peerid::PeerID& id) {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  auto finder = peers_.find(id);
  if (finder != peers_.end()) {
    return finder->second.get();
  }
  auto [iter, _] = peers_.emplace(id, std::make_unique<Peer>(id, this));
  GAUGE(peers, peers)->Set(peers_.size());
  return iter->second.get();
}

Peer* PeerManager::GetPeer(context::Context* ctx, const peerid::PeerID& id) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  auto finder = peers_.find(id);
  if (finder != peers_.end()) {
    return finder->second.get();
  }
  return nullptr;
}

Peer* PeerManager::GetPeerOrRst(context::Context* ctx, const peerid::PeerID& id) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  auto finder = peers_.find(id);
  if (finder != peers_.end()) {
    return finder->second.get();
  }
  Peer::SendRst(ctx, id);
  return nullptr;
}


std::pair<noise::DHState, e2e::Attestation*> PeerManager::ConnectionArgs(context::Context* ctx) {
  CHECK(init_success_.load());
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  auto att = ctx->Protobuf<e2e::Attestation>();
  *att = most_recent_attestation_;
  return std::make_pair(noise::CloneDHState(dhstate_), att);
}

error::Error PeerManager::ConnectToPeer(
    context::Context* ctx,
    const peerid::PeerID& to) {
  if (!init_success_.load()) {
    return COUNTED_ERROR(Peers_NoInit);
  }
  Peer* peer = CreatePeer(ctx, to);
  auto [dhstate, most_recent_attestation] = ConnectionArgs(ctx);
  RETURN_IF_ERROR(peer->Connect(ctx, dhstate, *most_recent_attestation));
  LOG(INFO) << ID() << " connecting to new peer " << to;
  return error::OK;
}

error::Error PeerManager::MaybeConnectToPeer(
    context::Context* ctx,
    const peerid::PeerID& to) {
  if (!init_success_.load()) {
    return COUNTED_ERROR(Peers_NoInit);
  }
  Peer* peer = CreatePeer(ctx, to);
  auto [dhstate, most_recent_attestation] = ConnectionArgs(ctx);
  auto [started_connection, err] = peer->MaybeConnect(ctx, dhstate, *most_recent_attestation);
  RETURN_IF_ERROR(err);
  if (started_connection) {
    LOG(INFO) << ID() << " connecting to new peer " << to;
  }
  return error::OK;
}

error::Error PeerManager::ResetPeer(
    context::Context* ctx,
    const peerid::PeerID& to) {
  if (!init_success_.load()) {
    return COUNTED_ERROR(Peers_NoInit);
  }
  Peer* peer = GetPeerOrRst(ctx, to);
  if (peer == nullptr) {
    return COUNTED_ERROR(Peers_ResetMissingPeer);
  }
  LOG(INFO) << "Resetting peer " << to;
  peer->Disconnect(ctx);
  return error::OK;
}

error::Error PeerManager::SendToPeer(
    context::Context* ctx,
    const peerid::PeerID& to,
    const e2e::EnclaveToEnclaveMessage& msg) {
  if (!init_success_.load()) {
    return COUNTED_ERROR(Peers_NoInit);
  }
  if (msg.connected()) {
    return COUNTED_ERROR(Peers_SendConnect);
  }
  Peer* peer = GetPeerOrRst(ctx, to);
  if (peer == nullptr) {
    return COUNTED_ERROR(Peers_SendBeforeConnect);
  }
  return peer->Send(ctx, msg);
}

error::Error PeerManager::RecvFromPeer(
    context::Context* ctx,
    const PeerMessage& msg,
    e2e::EnclaveToEnclaveMessage** decoded) {
  if (!init_success_.load()) {
    return COUNTED_ERROR(Peers_NoInit);
  }
  *decoded = nullptr;
  peerid::PeerID from;
  RETURN_IF_ERROR(from.FromString(msg.peer_id()));
  if (msg.inner_case() == PeerMessage::kSyn) {
    Peer* peer = CreatePeer(ctx, from);
    auto [dhstate, most_recent_attestation] = ConnectionArgs(ctx);
    RETURN_IF_ERROR(peer->Accept(ctx, dhstate, *most_recent_attestation, msg.syn(), decoded));
    LOG(INFO) << ID() << " accepted new peer " << from;
    return error::OK;
  }

  Peer* peer = msg.inner_case() == PeerMessage::kRst 
    ? GetPeer(ctx, from)
    : GetPeerOrRst(ctx, from);

  if (peer == nullptr) {
    return COUNTED_ERROR(Peers_RecvBeforeConnect);
  }  
  return peer->Recv(ctx, msg, decoded);
}

std::set<peerid::PeerID> PeerManager::ConnectedPeers(context::Context* ctx) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  std::set<peerid::PeerID> out;
  for (auto iter = peers_.cbegin(); iter != peers_.cend(); ++iter) {
    if (iter->second->CurrentState(ctx) == PEER_CONNECTED) {
      out.insert(iter->first);
    }
  }
  return out;
}

std::set<peerid::PeerID> PeerManager::AllPeers(context::Context* ctx) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  std::set<peerid::PeerID> out;
  for (auto iter = peers_.cbegin(); iter != peers_.cend(); ++iter) {
    out.insert(iter->first);
  }
  return out;
}

void PeerManager::SetPeerAttestationTimestamp(context::Context* ctx, util::UnixSecs secs, util::UnixSecs attestation_timeout) {
  auto old_secs = time_.exchange(secs);
  if (old_secs == secs) {
    return;
  } else if (old_secs > secs) {
    LOG(WARNING) << "PeerManager timestamp went backwards: " << old_secs << " -> " << secs;
  }
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  for (auto iter = peers_.begin(); iter != peers_.end(); ++iter) {
    iter->second->MaybeDisconnectIfAttestationTooOld(ctx, secs, attestation_timeout);
  }
}

void PeerManager::MinimumsUpdated(context::Context* ctx) {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  for (auto iter = peers_.begin(); iter != peers_.end(); ++iter) {
    if (auto err = iter->second->CheckMinimums(ctx, Minimums()); err != error::OK) {
      LOG(WARNING) << "Minimums for peer " << iter->first << " failed so disconnecting peer: " << err;
      iter->second->Disconnect(ctx);
    }
  }
}

error::Error PeerManager::CheckPeerMinimums(context::Context* ctx, const minimums::Minimums& to_check) const {
  ACQUIRE_LOCK(mu_, ctx, lock_peermanager);
  for (auto iter = peers_.begin(); iter != peers_.end(); ++iter) {
    if (auto err = iter->second->CheckMinimums(ctx, to_check); err != error::OK) {
      LOG(INFO) << "Minimums for peer " << iter->first << " failed: " << err;
      return err;
    }
  }
  return error::OK;
}

void PeerManager::PeerStatus(context::Context* ctx, const peerid::PeerID& id, ConnectionStatus* status) const {
  auto peer = GetPeer(ctx, id);
  if (peer == nullptr) { return; }
  peer->PopulateConnectionStatus(ctx, status);
}

}  // namespace svr2::remote
