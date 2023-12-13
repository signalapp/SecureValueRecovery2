// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "env/test/test.h"
#include "env/env.h"
#include "util/mutex.h"
#include <sys/random.h>
#include <string.h>
#include <atomic>
#include <mutex>

namespace svr2::env {
namespace test {

static const char* evidence_prefix = "EVIDENCE:";
static volatile std::atomic<uint32_t> random_gen;

class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment() : ::svr2::env::Environment() {}
  virtual ~Environment() {}
  virtual std::pair<e2e::Attestation, error::Error> Evidence(context::Context* ctx, const enclaveconfig::AttestationData& data) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    e2e::Attestation attestation;
    attestation.set_evidence(evidence_prefix + data.SerializeAsString());
    return std::make_pair(attestation, error::OK);
  }

  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    // We could do this reading in a while loop, but we expect it should be fine.
    // Rewrite this if tests fail because of it.
    CHECK(size > 0);
    uint8_t* ptr = reinterpret_cast<uint8_t*>(bytes);
    for (size_t i = 0; i < size; i++) {
      uint32_t next = std::atomic_fetch_add(&random_gen, 1U);
      // This keeps the sequence of bytes relatively non-repeating for the first 4GB.
      *ptr++ = (uint8_t)(next ^ (next >> 8) ^ (next >> 16) ^ (next >> 24));
    }
    return error::OK;
  }

  virtual std::pair<enclaveconfig::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    enclaveconfig::AttestationData out;
    const size_t prefix_len = strlen(evidence_prefix);
    if (attestation.evidence().size() < prefix_len) {
      return std::make_pair(out, COUNTED_ERROR(Env_AttestationFailure));
    }
    if (!out.ParseFromArray(attestation.evidence().data() + prefix_len, attestation.evidence().size() - prefix_len)) {
      return std::make_pair(out, COUNTED_ERROR(Env_AttestationFailure));
    }
    return std::make_pair(out, error::OK);
  }

  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const {
    EnclaveMessage m;
    MEASURE_CPU(ctx, cpu_env_sendmessage);
    CHECK(m.ParseFromString(msg));
    ACQUIRE_LOCK(mu_, ctx, lock_testenv_sendmessage);
    sent_messages_.push_back(std::move(m));
    return error::OK;
  }

  virtual void Log(int level, const std::string& msg) const {
    fprintf(stderr, "%s\n", msg.c_str());
  }

  std::vector<EnclaveMessage> SentMessages() {
    util::unique_lock ul(mu_);
    return std::move(sent_messages_);
  }

  virtual error::Error UpdateEnvStats() const {
    return error::OK;
  }

 private:
  mutable util::mutex mu_;
  mutable std::vector<EnclaveMessage> sent_messages_ GUARDED_BY(mu_);
};

std::vector<EnclaveMessage> SentMessages() {
  Environment* e = dynamic_cast<Environment*>(::svr2::env::environment.get());
  CHECK(e != nullptr);
  return e->SentMessages();
}

}  // namespace test

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::test::Environment>();
  environment->Init();
}

}  // namespace svr2::env
