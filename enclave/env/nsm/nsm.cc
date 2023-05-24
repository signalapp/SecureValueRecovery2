// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sodium/core.h>
#include <nsm.h>
#include <deque>
#include <stdio.h>
#include <sys/random.h>

#include "env/env.h"
#include "util/macros.h"
#include "util/constant.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/nitro.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "attestation/nitro/nitro.h"

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
    attestation::nitro::CoseSign1 cose_sign_1;
    attestation::nitro::AttestationDoc attestation_doc;

    error::Error err = error::OK;
    if (// Parse the evidence.
        error::OK != (err = cose_sign_1.ParseFromBytes(reinterpret_cast<const uint8_t*>(evidence.data()), evidence.size())) ||
        error::OK != (err = attestation_doc.ParseFromBytes(cose_sign_1.payload.data(), cose_sign_1.payload.size())) ||
        // Valiate the attestation doc.
        attestation_doc.public_key.size() != out.size() ||
        // Verify the evidence certificate chain and signature.
        error::OK != (err = attestation::nitro::Verify(attestation_doc, cose_sign_1, now)) ||
        // Verify that PCRs of remote match our own.
        !PCRsMatch(attestation_doc.pcrs)) {
      return std::make_pair(out, COUNTED_ERROR(Env_AttestationFailure));
    }
    std::copy(attestation_doc.public_key.begin(), attestation_doc.public_key.end(), out.begin());
    return std::make_pair(out, error::OK);
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

  virtual void Init() {
    ::svr2::env::Environment::Init();
    if (simulated_) return;
    // Get an initial set of evidence to pull our PCRs from.
    PublicKey k;
    enclaveconfig::RaftGroupConfig config;
    auto [att, err] = Evidence(k, config);
    CHECK(error::OK == err);
    // Parse evidence into an attestation doc.
    attestation::nitro::CoseSign1 cose_sign_1;
    CHECK(error::OK == cose_sign_1.ParseFromBytes(reinterpret_cast<const uint8_t*>(att.evidence().data()), att.evidence().size()));
    attestation::nitro::AttestationDoc attestation_doc;
    CHECK(error::OK == attestation_doc.ParseFromBytes(cose_sign_1.payload.data(), cose_sign_1.payload.size()));
    // Pull out the PCRs and store them.
    pcrs_ = std::move(attestation_doc.pcrs);
  }

 private:
  uint8_t PCRMatches(int index, const std::map<int, attestation::nitro::ByteString>& remotes) const {
    auto local = pcrs_.find(index);
    if (local == pcrs_.cend()) return false;
    auto remote = remotes.find(index);
    if (remote == remotes.cend()) return false;
    return util::ConstantTimeEquals(local->second, remote->second);
  }
  // Checks that security-relevant PCRs match locally and remotely.
  bool PCRsMatch(const std::map<int, attestation::nitro::ByteString>& remotes) const {
    // See discussion of PCRs at
    // https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
    // We only care about:
    //   0: Enclave image file - A contiguous measure of the contents of the image file, without the section data.
    //   1: Linux kernel and bootstrap - A contiguous measurement of the kernel and boot ramfs data.
    //   2: Application - A contiguous, in-order measurement of the user applications, without the boot ramfs.
    // We use & rather than && so that all three are processed without preemption.
    return PCRMatches(0, remotes) & PCRMatches(1, remotes) & PCRMatches(2, remotes);
  }

  int32_t nsm_fd_;
  bool simulated_;
  std::map<int, attestation::nitro::ByteString> pcrs_;
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
  environment->Init();
}

}  // namespace svr2::env
