// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_ENV_H__
#define __SVR2_ENV_ENV_H__

#include <string>
#include <array>
#include "proto/error.pb.h"
#include "proto/e2e.pb.h"
#include "proto/msgs.pb.h"
#include "proto/attestation.pb.h"
#include "util/macros.h"
#include "util/ticks.h"
#include "context/context.h"

namespace svr2::env {

typedef std::array<uint8_t, 32> PublicKey;

class Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment();
  virtual ~Environment() {}
  virtual void Init();
  // Given a 32-byte key, return evidence of that key (an OpenEnclave report).
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& attestation) const = 0;
  // Given evidence and endorsements, extract the key.
  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const = 0;
  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(
      void* bytes,
      size_t size) const = 0;
  // Send a message from enclave to host.  [msg] should be a serialized
  // EnclaveMessage.
  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const = 0;
  // Log a message to a logging framework.
  virtual void Log(int level, const std::string& msg) const = 0;
  // Update env-specific statistics.
  virtual error::Error UpdateEnvStats() const = 0;
  // FlushAllLogsIfAble attempts to log everything that's been seen by
  // Log() up to a place where operators can see it.
  virtual void FlushAllLogsIfAble() const = 0;
};

extern std::unique_ptr<Environment> environment;

static const bool SIMULATED = true;
static const bool NOT_SIMULATED = false;
void Init(bool is_simulated);

}  // namespace svr2::env

#endif  // __SVR2_ENV_ENV_H__
