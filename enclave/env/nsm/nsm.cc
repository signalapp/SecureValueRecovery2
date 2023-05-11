// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sodium/core.h>
#include <nsm.h>
#include <deque>
#include <stdio.h>
#include <sys/random.h>

#include "env/env.h"
#include "util/macros.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/nitro.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"

namespace svr2::env {
namespace nsm {
namespace {

static queue::Queue<std::string> output_messages(100);
static const char* SIMULATED_REPORT_PREFIX = "NITRO_SIMULATED_REPORT:";

class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : simulated_(simulated) {
    nsm_fd_ = nsm_lib_init();
  }
  virtual ~Environment() {
    nsm_lib_exit(nsm_fd_);
  }
  virtual std::pair<e2e::Attestation, error::Error> Evidence(const PublicKey& key, const enclaveconfig::RaftGroupConfig& config) const {
    e2e::Attestation out;
    if (simulated_) {
      out.set_evidence(SIMULATED_REPORT_PREFIX + util::ByteArrayToString(key));
      return std::make_pair(out, error::OK);
    }
    out.mutable_evidence()->resize(102400);
    uint32_t evidence_len = out.evidence().size();
    std::string config_serialized;
    if (!config.SerializeToString(&config_serialized)) {
      return std::make_pair(out, error::Env_SerializeCustomClaims);
    }
    if (ERROR_CODE_SUCCESS != nsm_get_attestation_doc(
        nsm_fd_,
        reinterpret_cast<const uint8_t*>(config_serialized.data()),
        config_serialized.size(),
        nullptr,
        0,
        key.data(),
        key.size(),
        reinterpret_cast<uint8_t*>(out.mutable_evidence()->data()),
        &evidence_len)) {
      return std::make_pair(out, error::Env_AttestationFailure);
    }
    out.mutable_evidence()->resize(evidence_len);
    return std::make_pair(out, error::OK);
  }

  // Given evidence and endorsements, extract the key.
  virtual std::pair<PublicKey, error::Error> Attest(
      util::UnixSecs now,
      const std::string& evidence,
      const std::string& endorsements) const {
    std::array<uint8_t, 32> out = {0};
    if (simulated_) {
      if (evidence.rfind(SIMULATED_REPORT_PREFIX, 0) != 0) {
        return std::make_pair(out, error::Env_AttestationFailure);
      }
      memcpy(out.data(), evidence.data() + strlen(SIMULATED_REPORT_PREFIX), out.size());
      return std::make_pair(out, error::OK);
    }
    return std::make_pair(out, error::General_Unimplemented);
  }

  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    if (simulated_) {
      while (size) {
        size_t got = getrandom(bytes, size, 0);
        if (got <= 0) { return error::Env_RandomBytes; }
        size -= got;
      }
      return error::OK;
    }
    uintptr_t received;
    uint8_t* u8ptr = reinterpret_cast<uint8_t*>(bytes);
    while (size) {
      received = size;
      if (ERROR_CODE_SUCCESS != nsm_get_random(nsm_fd_, u8ptr, &received)) {
        return error::Env_RandomBytes;
      }
      size -= received;
      u8ptr += received;
    }
    return error::OK;
  }

  virtual error::Error SendMessage(const std::string& msg) const {
    output_messages.Push(msg);
    return error::OK;
  }

  virtual void Log(int level, const std::string& msg) const {
    fprintf(stderr, "env::NSM LOG(%d): %s\n", level, msg.c_str());
  }

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

 private:
  int32_t nsm_fd_;
  bool simulated_;
};

}  // namespace

error::Error SendNsmMessages(socketwrap::Socket* sock) {
  while (true) {
    context::Context ctx;
    for (int i = 0; i < 100; i++) {
      auto out = ctx.Protobuf<nitro::OutboundMessage>();
      *out->mutable_out() = output_messages.Pop();
      RETURN_IF_ERROR(sock->WritePB(&ctx, *out));
    }
  }
}

}  // namespace nsm

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::nsm::Environment>(is_simulated);
}

}  // namespace svr2::env
