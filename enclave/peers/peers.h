// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_PEERS_PEERS_H__
#define __SVR2_PEERS_PEERS_H__

#include <unordered_map>
#include <string>
#include <array>
#include <memory>
#include <atomic>
#include <mutex>

#include "context/context.h"
#include "util/macros.h"
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"
#include "proto/e2e.pb.h"
#include "sip/hasher.h"
#include "noise/noise.h"
#include "peerid/peerid.h"
#include "groupclock/groupclock.h"
#include "util/mutex.h"

// Within the peer manager, peers can make the following state transitions.  The normal
// transition paths are:
//
//   Connect:  DISCONNECTED -> CONNECTING -> CONNECTED
//   Accept:   DISCONNECTED -> CONNECTED
//
// Nowever, note that:
//
// - From the CONNECTING/CONNECTED states, one can enter the DISCONNECTED
//   state should an error be encountered
// - From any state, one can enter CONNECTED by receiving a SYN and sending
//   a SYN/ACK.
// - From DISCONNECTED, one can enter CONNECTING by sending a SYN.
//
// By utilizing these mechanisms, we should be able to re-establish good connections
// should any connection state become invalid.
// 
//  ┌────────────────┐  error / recv:RST   ┌────────────────┐
//  │                │◄────────────────────┤                │
//  │  DISCONNECTED  │                     │  CONNECTING    │
//  │                ├────────────────────►│                │
//  └───────────┬────┘      send:SYN       └────┬────────┬──┘
//        ▲     │                               │        │
//        │     │                               │recv:   │recv:SYN
//        │     │                               │SYNACK  │send:SYNACK
//        │     │                               │        │
//        │     │    recv:SYN                   ▼        ▼
//        │     │    send:SYNACK           ┌────────────────┐
//        │     └─────────────────────────►│                │
//        │                                │  CONNECTED     │
//        └────────────────────────────────┤                │
//                   error / recv:RST      └────────────────┘
//
// (made with asciiflow)

namespace svr2::peers {

class PeerManager;

// Encapsulates the state for a single remote peer.
class Peer {
 public:
  DELETE_COPY_AND_ASSIGN(Peer);
  Peer(const peerid::PeerID& id, PeerManager* parent);

  const peerid::PeerID& ID() const { return id_; }
  error::Error Send(
      context::Context* ctx,
      const e2e::EnclaveToEnclaveMessage& msg) EXCLUDES(mu_);
  error::Error Recv(
      context::Context* ctx,
      const PeerMessage& msg,
      e2e::EnclaveToEnclaveMessage** decoded) EXCLUDES(mu_);

  // Connect is called on a newly created peer to request establishment of a new
  // connection to that remote party.
  error::Error Connect(
      context::Context* ctx,
      const noise::DHState& priv,
      const e2e::Attestation& attestation) EXCLUDES(mu_);
  // MaybeConnect is called when we're not sure if we're connected already
  // or not.  It won't disrupt an existing connection, but it will establish
  // a new one.  Returns a bool that says whether we attempted to start
  // the connection or not.
  std::pair<bool, error::Error> MaybeConnect(
      context::Context* ctx,
      const noise::DHState& priv,
      const e2e::Attestation& attestation) EXCLUDES(mu_);
  // Accept is called on a newly created peer to request establishment of a
  // remote-requested connection to that remote party.
  error::Error Accept(
      context::Context* ctx,
      const noise::DHState& priv,
      const e2e::Attestation& attestation,
      const std::string& syn,
      e2e::EnclaveToEnclaveMessage** decoded) EXCLUDES(mu_);
  // Disconnect the peer.
  void Disconnect(context::Context* ctx) EXCLUDES(mu_);
  // Disconnect the peer if its attestation timestamp is out of date.
  void MaybeDisconnectIfAttestationTooOld(context::Context* ctx, util::UnixSecs now, util::UnixSecs attestation_timeout) EXCLUDES(mu_);
  
  PeerState CurrentState(context::Context* ctx) const EXCLUDES(mu_);
  void PopulateConnectionStatus(context::Context* ctx, ConnectionStatus* status) const EXCLUDES(mu_);

  // Send a `rst` to the given peer ID.
  static void SendRst(context::Context* ctx, const peerid::PeerID& id) EXCLUDES(mu_);

 private:
  // Resets state to DISCONNECTED.
  void InternalDisconnect() REQUIRES(mu_);
  PeerState InternalCurrentState() const REQUIRES(mu_);

  // Connect is called on a newly created peer to request establishment of a new
  // connection to that remote party.
  error::Error InternalConnect(
      context::Context* ctx,
      const noise::DHState& priv,
      const e2e::Attestation& attestation) REQUIRES(mu_);

  // FinishConnection is called by Recv when [state==CONNECTING] to complete the handshake.
  error::Error FinishConnection(
      context::Context* ctx,
      const std::string& synack,
      e2e::EnclaveToEnclaveMessage** decoded) REQUIRES(mu_);

  // Reset to a state where we have a valid handshake_.
  error::Error Reset(
      const noise::DHState& priv,
      int noise_role) REQUIRES(mu_);

  error::Error CheckNextAttestation(const e2e::Attestation& a) REQUIRES(mu_);

  const peerid::PeerID id_;
  mutable util::mutex mu_;
  noise::HandshakeState handshake_ GUARDED_BY(mu_);
  noise::CipherState tx_ GUARDED_BY(mu_);
  noise::CipherState rx_ GUARDED_BY(mu_);
  const PeerManager* const parent_;
  util::UnixSecs last_attestation_ GUARDED_BY(mu_);
};

// PeerManager allows messages to be sent to and received from peers.
//
// Connecting to a new peer:
//
//   Connector                             Accepter
//  ----------------------------------------------------------
//   ConnectToPeer(accepter)
//   - encoded = handshake request ->  RecvFromPeer(connector, msg.syn)
//                                     - decoded = e2e.connect
//   RecvFromPeer(accepter, msg)   <-  - encoded = handshake response
//   - decoded = e2e.connect
//   - encoded = NULL
//
// The connector's first message contains the most recent attestation proof
// for the connector's communication public key, along with a Noise handshake
// for that key.
//
// The accepter's first message contains its attestation proof for its
// communication public key, as well as the noise handshake completion for
// this session.  The [decoded] message that comes out will have the
// [e2e.connect] flag set when the handshake is complete and the session
// is considered usable.
//
// After a client has connected, this manager can handle received messages
// by passing them to RecvFromPeer and handling the resulting [decoded]
// message, and can send messages by passing them through SendToPeer, then
// sending the resulting EnclaveMessage up to the host for processing.
class PeerManager {
 public:
  DELETE_COPY_AND_ASSIGN(PeerManager);
  PeerManager();
  ~PeerManager();

  error::Error Init(context::Context* ctx) EXCLUDES(mu_);

  error::Error RefreshAttestation(context::Context* ctx);

  // ConnectToPeer requests that a new connection be established to the given
  // PeerID.  This will replace any existing connections that might exist
  // with that peer with a new connection.
  error::Error ConnectToPeer(
      context::Context* ctx,
      const peerid::PeerID& to);

  // Try to establish a connection to [to] if one doesn't already exist.
  // If we're already connected or already attempting to connect, does nothing
  // and returns success.
  error::Error MaybeConnectToPeer(
      context::Context* ctx,
      const peerid::PeerID& to);

  // ResetPeer disconnects a peer and sends it an RST.
  error::Error ResetPeer(
      context::Context* ctx,
      const peerid::PeerID& to);

  // SendToPeer takes in a serialized protobuf to send to [to].  If
  // [msg.connect] is set, then this is requesting a new connection to [to]
  // rather than sending on an existing channel.
  // Note:  does not actually send the message in question, just encodes it.
  error::Error SendToPeer(
      context::Context* ctx,
      const peerid::PeerID& to,
      const e2e::EnclaveToEnclaveMessage& msg);

  // RecvFromPeer takes in a PeerMessage and decodes it.  If that
  // message contains a EnclaveToEnclaveMessage, that message is instantiated
  // in the provided [arena] and returned as [*decoded].  If not, [*decoded]
  // will be NULL.  If [*encoded] is not null, it should be sent up to the
  // host.
  // If this message establishes a connection, [*decoded.connect] will be set.
  error::Error RecvFromPeer(
      context::Context* ctx,
      const PeerMessage& msg,
      e2e::EnclaveToEnclaveMessage** decoded);

  // Returns the local identifier (public key) that remote peers use to connect
  // to this peer manager.
  const peerid::PeerID& ID() const NO_THREAD_SAFETY_ANALYSIS;

  // Get the current state of a peer ID.
  PeerState PeerState(context::Context* ctx, const peerid::PeerID& id) const;

  std::set<peerid::PeerID> ConnectedPeers(context::Context* ctx) const;
  std::set<peerid::PeerID> AllPeers(context::Context* ctx) const;
  void PeerStatus(context::Context* ctx, const peerid::PeerID& id, ConnectionStatus* status) const;

  void SetPeerAttestationTimestamp(context::Context* ctx, util::UnixSecs secs, util::UnixSecs attestation_timeout) EXCLUDES(mu_);

  util::UnixSecs CurrentTime() const { return time_.load(); }

 private:
  std::pair<noise::DHState, e2e::Attestation*> ConnectionArgs(context::Context* ctx) EXCLUDES(mu_);

  // CreatePeer returns a peer for the given ID, creating it if necessary.
  Peer* CreatePeer(context::Context* ctx, const peerid::PeerID& id) EXCLUDES(mu_);
  // GetPeer returns the peer associated with the given ID
  Peer* GetPeer(context::Context* ctx, const peerid::PeerID& id) const EXCLUDES(mu_);
  // GetPeerOrRst returns the peer associated with the given ID, sending
  // a RST to that peer if it doesn't exist.
  Peer* GetPeerOrRst(context::Context* ctx, const peerid::PeerID& id) const EXCLUDES(mu_);

  mutable util::mutex mu_;
  // To simplify multi-threaded logic, a peer once added to `peers_` will
  // never be removed.
  std::unordered_map<peerid::PeerID, std::unique_ptr<Peer>, peerid::PeerIDHasher> peers_ GUARDED_BY(mu_);
  noise::DHState dhstate_ GUARDED_BY(mu_);
  peerid::PeerID id_ GUARDED_BY(mu_);
  e2e::Attestation most_recent_attestation_ GUARDED_BY(mu_);
  std::atomic<bool> init_success_;
  std::atomic<util::UnixSecs> time_;
};

}  // namespace svr2::peers

#endif  // __SVR2_PEERS_PEERS_H__
