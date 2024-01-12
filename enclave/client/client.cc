// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "client/client.h"

#include <atomic>

#include "env/env.h"
#include "util/log.h"
#include "util/hex.h"
#include "metrics/metrics.h"

namespace svr2::client {

static std::atomic<uint64_t> id_gen{1};

const NoiseProtocolId client_protocol = {
    .prefix_id = NOISE_PREFIX_STANDARD,
    .pattern_id = NOISE_PATTERN_NK,
    .dh_id = NOISE_DH_CURVE25519,
    .cipher_id = NOISE_CIPHER_CHACHAPOLY,
    .hash_id = NOISE_HASH_SHA256,
    .hybrid_id = 0,
};

Client::Client(const std::string& authenticated_id)
    : hs_(noise::WrapHandshakeState(nullptr)),
      tx_(noise::WrapCipherState(nullptr)),
      rx_(noise::WrapCipherState(nullptr)),
      id_(id_gen.fetch_add(1)),
      authenticated_id_(authenticated_id) {
}

Client::~Client() {
}

error::Error Client::Init(const noise::DHState& dhstate, const e2e::Attestation& attestation) {
  util::unique_lock lock(mu_);
  NoiseHandshakeState* hs;
  if (NOISE_ERROR_NONE != noise_handshakestate_new_by_id(&hs, &client_protocol, NOISE_ROLE_RESPONDER)) {
    return COUNTED_ERROR(Client_HandshakeState);
  }
  auto hs_wrap = noise::WrapHandshakeState(hs);
  if (NOISE_ERROR_NONE != noise_dhstate_copy(
      noise_handshakestate_get_local_keypair_dh(hs),
      dhstate.get())) {
    return COUNTED_ERROR(Client_CopyDHState);
  }
  if (NOISE_ERROR_NONE != noise_handshakestate_start(hs)) {
    return COUNTED_ERROR(Client_HandshakeStart);
  }
  hs_start_.mutable_test_only_pubkey()->resize(32, '\0');
  if (NOISE_ERROR_NONE != noise_dhstate_get_public_key(
      dhstate.get(),
      noise::StrU8Ptr(hs_start_.mutable_test_only_pubkey()),
      hs_start_.mutable_test_only_pubkey()->size())) {
    return COUNTED_ERROR(Client_ExtractPublicKey);
  }
  *hs_start_.mutable_evidence() = attestation.evidence();
  *hs_start_.mutable_endorsement() = attestation.endorsements();
  hs_.swap(hs_wrap);
  return error::OK;
}

std::pair<std::string, error::Error> Client::FinishHandshake(context::Context* ctx, const std::string& data) {
  ACQUIRE_LOCK(mu_, ctx, lock_client);
  MEASURE_CPU(ctx, cpu_client_hs_finish);
  if (!hs_.get() || tx_.get() || rx_.get()
      || noise_handshakestate_get_action(hs_.get()) != NOISE_ACTION_READ_MESSAGE) {
    return std::make_pair("", COUNTED_ERROR(Client_HandshakeState));
  }
  std::string buffer = data;
  NoiseBuffer read_buf = noise::BufferInputFromString(&buffer);
  if (NOISE_ERROR_NONE != noise_handshakestate_read_message(hs_.get(), &read_buf, nullptr)) {
    return std::make_pair("", COUNTED_ERROR(Client_FinishReadHandshake));
  }
  if (NOISE_ACTION_WRITE_MESSAGE != noise_handshakestate_get_action(hs_.get())) {
    return std::make_pair("", COUNTED_ERROR(Client_HandshakeState));
  }
  buffer.resize(noise::HANDSHAKE_INIT_SIZE, '\0');
  NoiseBuffer write_buf = noise::BufferOutputFromString(&buffer);
  if (NOISE_ERROR_NONE != noise_handshakestate_write_message(hs_.get(), &write_buf, nullptr)) {
    return std::make_pair("", COUNTED_ERROR(Client_FinishWriteHandshake));
  }
  buffer.resize(write_buf.size);
  if (NOISE_ACTION_SPLIT != noise_handshakestate_get_action(hs_.get())) {
    return std::make_pair("", COUNTED_ERROR(Client_HandshakeState));
  }
  NoiseCipherState* tx;
  NoiseCipherState* rx;
  if (NOISE_ERROR_NONE != noise_handshakestate_split(hs_.get(), &tx, &rx)) {
    return std::make_pair("", COUNTED_ERROR(Client_FinishSplit));
  }
  tx_.reset(tx);
  rx_.reset(rx);
  hs_.reset(nullptr);
  return std::make_pair(buffer, error::OK);
}

error::Error Client::DecryptRequest(context::Context* ctx, const std::string& data, google::protobuf::MessageLite* request) {
  ACQUIRE_LOCK(mu_, ctx, lock_client);
  MEASURE_CPU(ctx, cpu_client_decrypt);
  if (hs_.get() || !tx_.get() || !rx_.get()) {
    return COUNTED_ERROR(Client_DecryptState);
  }
  auto [plaintext, err] = noise::Decrypt(rx_.get(), data);
  if (err != error::OK) {
    return err;
  }
  if (!request->ParseFromString(plaintext)) {
    return COUNTED_ERROR(Client_DecryptParse);
  }
  return error::OK;
}

std::pair<std::string, error::Error> Client::EncryptResponse(context::Context* ctx, const google::protobuf::MessageLite& response) {
  ACQUIRE_LOCK(mu_, ctx, lock_client);
  MEASURE_CPU(ctx, cpu_client_encrypt);
  if (hs_.get() || !tx_.get() || !rx_.get()) {
    return std::make_pair("", COUNTED_ERROR(Client_EncryptState));
  }
  std::string plaintext;
  if (!response.SerializeToString(&plaintext)) {
    return std::make_pair("", COUNTED_ERROR(Client_EncryptSerialize));
  }
  return noise::Encrypt(tx_.get(), plaintext);
}

std::pair<Client*, error::Error> ClientManager::NewClient(context::Context* ctx, const std::string& authenticated_id) {
  MEASURE_CPU(ctx, cpu_client_hs_start);
  std::unique_ptr<Client> c(new Client(authenticated_id));
  auto [dhstate, attestation] = ClientArgs(ctx);
  error::Error err = c->Init(dhstate, attestation);
  if (err != error::OK) {
    return std::make_pair(nullptr, err);
  }
  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  Client* ptr = c.get();
  clients_[ptr->ID()] = std::move(c);
  GAUGE(client, clients)->Set(clients_.size());
  COUNTER(client, created)->Increment();
  return std::make_pair(ptr, error::OK);
}

Client* ClientManager::GetClient(context::Context* ctx, ClientID id) const {
  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  auto find = clients_.find(id);
  if (find == clients_.end()) { return nullptr; }
  return find->second.get();
}

bool ClientManager::RemoveClient(context::Context* ctx, ClientID id) {
  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  auto find = clients_.find(id);
  if (find == clients_.end()) { return false; }
  clients_.erase(find);
  GAUGE(client, clients)->Set(clients_.size());
  COUNTER(client, closed)->Increment();
  return true;
}

noise::DHState ClientManager::NewDHState() {
  COUNTER(client, new_dh_state)->Increment();
  noise::DHState out = noise::WrapDHState(nullptr);
  NoiseDHState* dhstate;
  if (NOISE_ERROR_NONE != noise_dhstate_new_by_id(&dhstate, client::client_protocol.dh_id)) {
    return out;
  }
  noise::DHState client_dh = noise::WrapDHState(dhstate);
  if (NOISE_ERROR_NONE != noise_dhstate_generate_keypair(dhstate)) {
    return out;
  }
  client_dh.swap(out);
  return out;
}

error::Error ClientManager::RotateKeyAndRefreshAttestation(context::Context* ctx, const enclaveconfig::RaftGroupConfig& config) {
  auto dhstate = NewDHState();
  auto [attestation, err] = GetAttestation(ctx, dhstate, config);
  if (err != error::OK) {
    COUNTER(client, key_rotate_failure)->Increment();
    return err;
  }

  LOG(DEBUG) << "New client attestation: "
      << "evidence:'" << util::ToHex(attestation.evidence()) << "' "
      << "endorsements:'" << util::ToHex(attestation.endorsements()) << "'";

  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  dhstate_.swap(dhstate);
  attestation_.CopyFrom(attestation);
  COUNTER(client, key_rotate_success)->Increment();
  return error::OK;
}

error::Error ClientManager::RefreshAttestation(context::Context* ctx, const enclaveconfig::RaftGroupConfig& config) {
  auto [dhstate, _] = ClientArgs(ctx);
  auto [attestation, err] = GetAttestation(ctx, dhstate, config);
  if (err != error::OK) {
    COUNTER(client, attestation_refresh_failure)->Increment();
    return err;
  }

  LOG(DEBUG) << "New client attestation: "
      << "evidence:'" << util::ToHex(attestation.evidence()) << "' "
      << "endorsements:'" << util::ToHex(attestation.endorsements()) << "'";

  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  attestation_.CopyFrom(attestation);
  // There's a chance that a RotateKeyAndRefreshAttestation call
  // could have happened between when we got dhstate and when we're
  // setting attestation here... reset to the one we received just
  // in case.
  dhstate_.swap(dhstate);
  COUNTER(client, attestation_refresh_success)->Increment();
  return error::OK;
}

std::pair<e2e::Attestation, error::Error> ClientManager::GetAttestation(context::Context* ctx, const noise::DHState& dhstate, const enclaveconfig::RaftGroupConfig& config) {
  attestation::AttestationData att;
  att.mutable_public_key()->resize(32);
  e2e::Attestation attestation;
  // get attestation for its public key
  if (NOISE_ERROR_NONE != noise_dhstate_get_public_key(
      dhstate.get(),
      reinterpret_cast<uint8_t*>(att.mutable_public_key()->data()),
      32)) {
    return std::make_pair(attestation, error::Peers_NewKeyPublic);
  }
  att.mutable_group_config()->MergeFrom(config);
  return env::environment->Evidence(ctx, att);
}

std::pair<noise::DHState, e2e::Attestation> ClientManager::ClientArgs(context::Context* ctx) const {
  ACQUIRE_LOCK(mu_, ctx, lock_clientmanager);
  return std::make_pair(noise::CloneDHState(dhstate_), attestation_);
}

}  // namespace svr2::client
