// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CLIENT_CLIENT_H__
#define __SVR2_CLIENT_CLIENT_H__

#include <mutex>
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"
#include "proto/e2e.pb.h"
#include "noise/noise.h"
#include "sip/hasher.h"
#include "util/endian.h"
#include "util/mutex.h"
#include "context/context.h"
#include "db/db.h"

namespace svr2::client {

class ClientManager;
typedef uint64_t ClientID;
extern const NoiseProtocolId client_protocol;

class Client {
 public:
  ClientID ID() const { return id_; }
  // Returns ClientHandshakeStart, with std::move semantics, so this
  // function should be used only once.
  ClientHandshakeStart MovedHandshakeStart() EXCLUDES(mu_) {
    util::unique_lock lock(mu_);
    return std::move(hs_start_);
  }

  bool Handshaking() const {
    util::unique_lock lock(mu_);
    return hs_.get() != nullptr;
  }
  std::pair<std::string, error::Error> FinishHandshake(context::Context* ctx, const std::string& data) EXCLUDES(mu_);

  error::Error DecryptRequest(context::Context* ctx, const std::string& data, google::protobuf::MessageLite* request) EXCLUDES(mu_);
  std::pair<std::string, error::Error> EncryptResponse(context::Context* ctx, const google::protobuf::MessageLite& response) EXCLUDES(mu_);

  db::DB::ClientState* State() { return cs_.get(); }

 private:
  ~Client();
  explicit Client(std::unique_ptr<db::DB::ClientState> cs);
  error::Error Init(const noise::DHState& dhstate, const e2e::Attestation& attestation) EXCLUDES(mu_);
  friend class ClientManager;
  friend std::unique_ptr<Client>::deleter_type;

  mutable util::mutex mu_;
  ClientHandshakeStart hs_start_ GUARDED_BY(mu_);
  noise::HandshakeState hs_ GUARDED_BY(mu_);
  noise::CipherState tx_ GUARDED_BY(mu_);
  noise::CipherState rx_ GUARDED_BY(mu_);
  const size_t id_;
  std::unique_ptr<db::DB::ClientState> cs_;
};

class ClientManager {
 public:
  ClientManager(noise::DHState dhstate) : dhstate_(std::move(dhstate)) {}
  error::Error RefreshAttestation(context::Context* ctx, const enclaveconfig::RaftGroupConfig& config) EXCLUDES(mu_);
  error::Error RotateKeyAndRefreshAttestation(context::Context* ctx, const enclaveconfig::RaftGroupConfig& config) EXCLUDES(mu_);
  static noise::DHState NewDHState();

  std::pair<Client*, error::Error> NewClient(
      context::Context* ctx,
      std::unique_ptr<db::DB::ClientState> cs) EXCLUDES(mu_);
  Client* GetClient(context::Context* ctx, ClientID id) const EXCLUDES(mu_);
  // Deallocate and remove a client by its ID.
  // Client pointers are owned by the ClientManager and can only be deallocated
  // via a call to RemoveClient.
  bool RemoveClient(context::Context* ctx, ClientID id) EXCLUDES(mu_);

 private:
  std::pair<noise::DHState, e2e::Attestation> ClientArgs(context::Context* ctx) const EXCLUDES(mu_);
  static std::pair<e2e::Attestation, error::Error> GetAttestation(context::Context* ctx, const noise::DHState& dhstate, const enclaveconfig::RaftGroupConfig& config);
  
  mutable util::mutex mu_;
  noise::DHState dhstate_ GUARDED_BY(mu_);
  e2e::Attestation attestation_ GUARDED_BY(mu_);
  std::unordered_map<ClientID, std::unique_ptr<Client>> clients_ GUARDED_BY(mu_);
};

}  // namespace svr2::client

#endif  // __SVR2_CLIENT_CLIENT_H__
