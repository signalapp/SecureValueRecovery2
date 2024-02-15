// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <nsm.h>
#include <stdio.h>
#include <sys/random.h>
#include <sstream>

#include "env/env.h"
#include "env/socket/socket.h"
#include "util/macros.h"
#include "util/constant.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "attestation/nitro/nitro.h"
#include "util/mutex.h"

namespace svr2::env {
namespace nsm {
namespace {

class Environment : public ::svr2::env::socket::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::socket::Environment(simulated), nsm_fd_(0) {
    nsm_fd_ = nsm_lib_init();
  }
  virtual ~Environment() {
    nsm_lib_exit(nsm_fd_);
  }
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    if (simulated()) {
      return SimulatedEvidence(ctx, data);
    }
    e2e::Attestation out;
    out.mutable_evidence()->resize(102400);
    uint32_t evidence_len = out.evidence().size();
    std::string data_serialized;
    if (!data.SerializeToString(&data_serialized)) {
      return std::make_pair(out, error::Env_SerializeCustomClaims);
    }
    if (ERROR_CODE_SUCCESS != nsm_get_attestation_doc(
        nsm_fd_,
        reinterpret_cast<const uint8_t*>(data_serialized.data()),
        data_serialized.size(),
        nullptr,
        0,
        nullptr,
        0,
        reinterpret_cast<uint8_t*>(out.mutable_evidence()->data()),
        &evidence_len)) {
      return std::make_pair(out, error::Env_AttestationFailure);
    }
    out.mutable_evidence()->resize(evidence_len);
    return std::make_pair(out, error::OK);
  }

  // Given evidence and endorsements, extract attestation data.
  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    if (simulated()) {
      return SimulatedAttest(ctx, now, attestation);
    }
    attestation::AttestationData out;
    attestation::nitro::CoseSign1 cose_sign_1;
    attestation::nitro::AttestationDoc attestation_doc;

    error::Error err = error::OK;
    if (// Parse the evidence.
        error::OK != (err = cose_sign_1.ParseFromBytes(reinterpret_cast<const uint8_t*>(attestation.evidence().data()), attestation.evidence().size())) ||
        error::OK != (err = attestation_doc.ParseFromBytes(cose_sign_1.payload.data(), cose_sign_1.payload.size())) ||
        // Verify the evidence certificate chain and signature.
        error::OK != (err = attestation::nitro::Verify(attestation_doc, cose_sign_1, now)) ||
        // Verify that PCRs of remote match our own.
        !PCRsMatch(attestation_doc.pcrs) ||
        // Parse the attestation data.
        !out.ParseFromArray(attestation_doc.user_data.data(), attestation_doc.user_data.size())) {
      return std::make_pair(out, COUNTED_ERROR(Env_AttestationFailure));
    }
    return std::make_pair(out, error::OK);
  }

  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    if (simulated()) {
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

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

  virtual void Init() {
    ::svr2::env::socket::Environment::Init();
    if (simulated()) return;
    // Get an initial set of evidence to pull our PCRs from.
    attestation::AttestationData data;
    data.mutable_public_key()->resize(sizeof(env::PublicKey));
    context::Context ctx;
    auto [att, err] = Evidence(&ctx, data);
    CHECK(error::OK == err);
    // Parse evidence into an attestation doc.
    attestation::nitro::CoseSign1 cose_sign_1;
    CHECK(error::OK == cose_sign_1.ParseFromBytes(reinterpret_cast<const uint8_t*>(att.evidence().data()), att.evidence().size()));
    attestation::nitro::AttestationDoc attestation_doc;
    CHECK(error::OK == attestation_doc.ParseFromBytes(cose_sign_1.payload.data(), cose_sign_1.payload.size()));
    // Pull out the PCRs and store them.
    pcrs_ = std::move(attestation_doc.pcrs);
    for (auto iter = pcrs_.cbegin(); iter != pcrs_.cend(); ++iter) {
      std::stringstream ss;
      ss << "PCR" << iter->first << ": " << util::ToHex(iter->second);
      Log(enclaveconfig::LOG_LEVEL_INFO, ss.str());
    }
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
    //      Note:  0 can change when an otherwise exactly-the-same image is rebuilt, due to changes in in-image
    //      timestamps, etc.  However, it could also change with changes to shared libraries etc, so we do
    //      check against this.  Be careful, though, that attempts to rebuild the same SVR code may result in
    //      mismatches here.
    //   1: Linux kernel and bootstrap - A contiguous measurement of the kernel and boot ramfs data.
    //   2: Application - A contiguous, in-order measurement of the user applications, without the boot ramfs.
    // We use & rather than && so that all three are processed without preemption.
    return PCRMatches(0, remotes) & PCRMatches(1, remotes) & PCRMatches(2, remotes);
  }

  int32_t nsm_fd_;
  std::map<int, attestation::nitro::ByteString> pcrs_;
};

}  // namespace
}  // namespace nsm

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::nsm::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
