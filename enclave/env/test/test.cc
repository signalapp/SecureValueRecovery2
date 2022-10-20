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
  virtual std::pair<e2e::Attestation, error::Error> Evidence(const PublicKey& key, const enclaveconfig::RaftGroupConfig& config) const {
    e2e::Attestation attestation;
    attestation.set_evidence(evidence_prefix + std::string(reinterpret_cast<const char*>(key.data()), key.size()));
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

  virtual std::pair<PublicKey, error::Error> Attest(
      util::UnixSecs now,
      const std::string& evidence,
      const std::string& endorsements) const {
    PublicKey out = {0};
    if (evidence.size() != strlen(evidence_prefix) + out.size()
        || evidence.substr(0, strlen(evidence_prefix)) != evidence_prefix) {
      return std::make_pair(out, error::Env_AttestationFailure);
    }
    memcpy(out.data(), evidence.data() + strlen(evidence_prefix), out.size());
    return std::make_pair(out, error::OK);
  }

  virtual error::Error SendMessage(const std::string& msg) const {
    util::unique_lock ul(mu_);
    EnclaveMessage m;
    CHECK(m.ParseFromString(msg));
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
