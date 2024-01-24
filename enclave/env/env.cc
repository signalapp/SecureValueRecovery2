// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "env/env.h"
#include "util/macros.h"
#include <sodium/core.h>
#include <sodium/randombytes.h>
#include <stdio.h>

namespace svr2::env {

namespace {

class UnsetEnvironment : public Environment {
 public:
  virtual ~UnsetEnvironment() {}
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");

    return std::make_pair(e2e::Attestation(), error::General_Unimplemented);
  }
  // Given evidence and endorsements, extract the key.
  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    attestation::AttestationData out;
    return std::make_pair(out, error::General_Unimplemented);
  }
  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    return error::General_Unimplemented;
  }

  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    return error::General_Unimplemented;
  }

  virtual void Log(int level, const std::string& msg) const {
    // We allow logging to be called before Init.
    fprintf(stderr, "Pre-env::Init LOG(%d): %s\n", level, msg.c_str());
  }

  virtual void FlushAllLogsIfAble() const {
  }

  virtual error::Error UpdateEnvStats() const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    return error::General_Unimplemented;
  }
};

const char* env_randombytes_name() { return "env"; }
uint32_t env_randombytes_uint32() {
  uint32_t out;
  CHECK(error::OK == environment->RandomBytes(&out, sizeof(out)));
  return out;
}
void env_randombytes_bytes(void* const buf, const size_t size) {
  CHECK(error::OK == environment->RandomBytes(buf, size));
}
randombytes_implementation sodium_randombytes_impl = {
  .implementation_name = env_randombytes_name,
  .random = env_randombytes_uint32,
  .buf = env_randombytes_bytes,
};

}  // namespace

std::unique_ptr<Environment> environment(new UnsetEnvironment());

Environment::Environment() {
}

void Environment::Init() {
  // sodium_init returns 0 or 1 on success, -1 on failure.
  CHECK(0 == randombytes_set_implementation(&sodium_randombytes_impl));
  CHECK(sodium_init() >= 0);
}

}  // namespace svr2::env
