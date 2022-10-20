// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "env/env.h"
#include "util/macros.h"
#include <sodium/core.h>
#include <sodium/randombytes.h>

namespace svr2::env {

namespace {

class UnsetEnvironment : public Environment {
 public:
  virtual ~UnsetEnvironment() {}
  virtual std::pair<e2e::Attestation, error::Error> Evidence(const PublicKey& key, const enclaveconfig::RaftGroupConfig& config) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");

    return std::make_pair(e2e::Attestation(), error::General_Unimplemented);
  }
  // Given evidence and endorsements, extract the key.
  virtual std::pair<PublicKey, error::Error> Attest(
      util::UnixSecs now,
      const std::string& evidence,
      const std::string& endorsements) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    std::array<uint8_t, 32> out = {0};
    return std::make_pair(out, error::General_Unimplemented);
  }
  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    return error::General_Unimplemented;
  }

  virtual error::Error SendMessage(const std::string& msg) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
    return error::General_Unimplemented;
  }

  virtual void Log(int level, const std::string& msg) const {
    CHECK(nullptr == "env::Init not called, environment not initiated");
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
