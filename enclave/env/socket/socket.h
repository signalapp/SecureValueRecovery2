// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_SOCKET_SOCKET_H__
#define __SVR2_ENV_SOCKET_SOCKET_H__

#include "socketwrap/socket.h"
#include "proto/error.pb.h"
#include "env/env.h"

namespace svr2::env::socket {

class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated);
  virtual ~Environment();
  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const;
  virtual void Log(int level, const std::string& msg) const;
  virtual void FlushAllLogsIfAble() const;
  virtual error::Error RandomBytes(void* bytes, size_t size) const;

 protected:
  bool simulated() const { return simulated_; }
  std::pair<e2e::Attestation, error::Error> SimulatedEvidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const;
  std::pair<attestation::AttestationData, error::Error> SimulatedAttest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const;


 private:
  bool simulated_;
};

// Send all outstanding messages, in order, up to the host.
// Blocks forever.
error::Error SendSocketMessages(socketwrap::Socket* sock);

}  // namespace svr2::env::nsm

#endif  // __SVR2_ENV_SOCKET_SOCKET_H__
