// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium/crypto_hash_sha256.h>

#include "attestation/sev/sev.h"
#include "env/env.h"
#include "env/socket/socket.h"
#include "env/sev/linux_types.h"
#include "util/macros.h"
#include "util/constant.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/mutex.h"
#include "util/endian.h"
#include "util/log.h"

namespace svr2::env {
namespace sev {
namespace {

static const char* SIMULATED_REPORT_PREFIX = "SEV_SIMULATED_REPORT:";

class Environment : public ::svr2::env::socket::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : sev_fd_(0), simulated_(simulated) {
    sev_fd_ = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    CHECK(sev_fd_ > 0);
  }
  virtual ~Environment() {
    close(sev_fd_);
  }
  // Attestation.evidence will be:
  //   concat(SEV-SNP report, config.serialized())
  // - `SEV-SNP report` and `key` are constant-sized (1184 and 32 bytes, respectively).
  // - The report's `report_data` is concat(key, SHA256(config.serialized())).
  //
  // Attestation evidence is the extended evidence provided to the VM
  // by SNP_SET_EXT_CONFIG, which should be the certificate chain for
  // this report.
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const PublicKey& key,
      const enclaveconfig::RaftGroupConfig& config) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    e2e::Attestation out;
    if (simulated_) {
      out.set_evidence(SIMULATED_REPORT_PREFIX + util::ByteArrayToString(key));
      return std::make_pair(out, error::OK);
    }

    struct snp_ext_report_req req;
    struct snp_report_resp resp;
    struct snp_guest_request_ioctl guest_req;
    struct msg_report_resp* report_resp = reinterpret_cast<struct msg_report_resp*>(&resp.data);
    uint8_t certs[SEV_FW_BLOB_MAX_SIZE];
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(&guest_req, 0, sizeof(guest_req));
    memset(certs, 0, sizeof(certs));
    req.certs_address = reinterpret_cast<__u64>(&certs[0]);
    req.certs_len = sizeof(certs);

    CHECK(sizeof(req.data.user_data) >= key.size() + crypto_hash_sha256_BYTES);
    memcpy(req.data.user_data, key.data(), key.size());
    std::string extra_data = config.SerializeAsString();
    crypto_hash_sha256_state sha256;
    crypto_hash_sha256_init(&sha256);
    crypto_hash_sha256_update(&sha256, reinterpret_cast<const uint8_t*>(extra_data.data()), extra_data.size());
    crypto_hash_sha256_final(&sha256, req.data.user_data + sizeof(PublicKey));

    guest_req.msg_version = 1;
    guest_req.req_data = reinterpret_cast<__u64>(&req);
    guest_req.resp_data = reinterpret_cast<__u64>(&resp);

    int ioctl_ret = ioctl(sev_fd_, SNP_GET_EXT_REPORT, &guest_req);
    {
      auto e = errno;
      LOG(INFO) << "SEV_IOCTL OUTPUT:"
          << " ioctl_ret=" << ioctl_ret
          << " fw_error=" << guest_req.fw_error
          << " vmm_error=" << guest_req.vmm_error
          << " status=" << report_resp->status
          << " errno_str=" << strerror(e);
    }

    error::Error err = error::OK;
    if (ioctl_ret < 0) {
      return std::make_pair(out, COUNTED_ERROR(Sev_ReportIOCTLFailure));
    } else if (0 != guest_req.fw_error || 0 != guest_req.vmm_error || 0 != report_resp->status) {
      return std::make_pair(out, COUNTED_ERROR(Sev_FirmwareError));
    } else if (sizeof(report_resp->report) != report_resp->report_size) {
      return std::make_pair(out, COUNTED_ERROR(Sev_ReportSizeMismatch));
    } else if (error::OK != (err = attestation::sev::ResizeCertificates(certs, &req.certs_len))) {
      return std::make_pair(out, err);
    }
    out.mutable_evidence()->resize(sizeof(report_resp->report));
    memcpy(out.mutable_evidence()->data(), reinterpret_cast<const char*>(&report_resp->report), sizeof(report_resp->report));
    *out.mutable_evidence() += extra_data;
    out.mutable_endorsements()->resize(req.certs_len);
    memcpy(out.mutable_endorsements()->data(), reinterpret_cast<const char*>(certs), req.certs_len);

    auto r = &report_resp->report;
    LOG(INFO) << "SEV REPORT:"
        << " version:" << util::ValueToHex(r->version)
        << " guest_svn:" << util::ValueToHex(r->guest_svn)
        << " policy:" << util::ValueToHex(r->policy)
        << " family_id:" << util::BytesToHex(r->family_id, sizeof(r->family_id))
        << " image_id:" << util::BytesToHex(r->image_id, sizeof(r->image_id))
        << " vmpl:" << util::ValueToHex(r->vmpl)
        << " signature_algo:" << util::ValueToHex(r->signature_algo)
        << " platform_version:" << util::ValueToHex(r->platform_version.raw)
        << " platform_info:" << util::ValueToHex(r->platform_info)
        << " flags:" << util::ValueToHex(r->flags)
        << " report_data:" << util::BytesToHex(r->report_data, sizeof(r->report_data))
        << " measurement:" << util::BytesToHex(r->measurement, sizeof(r->measurement))
        << " host_data:" << util::BytesToHex(r->host_data, sizeof(r->host_data))
        << " id_key_digest:" << util::BytesToHex(r->id_key_digest, sizeof(r->id_key_digest))
        << " author_key_digest:" << util::BytesToHex(r->author_key_digest, sizeof(r->author_key_digest))
        << " report_id:" << util::BytesToHex(r->report_id, sizeof(r->report_id))
        << " report_id_ma:" << util::BytesToHex(r->report_id_ma, sizeof(r->report_id_ma))
        << " reported_tcb:" << util::ValueToHex(r->reported_tcb.raw)
        << " chip_id:" << util::BytesToHex(r->chip_id, sizeof(r->chip_id))
        << " signature.r:" << util::BytesToHex(r->signature.r, sizeof(r->signature.r))
        << " signature.s:" << util::BytesToHex(r->signature.s, sizeof(r->signature.s));
    LOG(DEBUG) << "Attestation:"
        << " evidence:" << util::ToHex(out.evidence())
        << " endorsements:" << util::ToHex(out.endorsements());

    return std::make_pair(out, error::OK);
  }

  // Given evidence and endorsements, extract the key.
  virtual std::pair<PublicKey, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    std::array<uint8_t, 32> out = {0};
    if (simulated_) {
      if (attestation.evidence().rfind(SIMULATED_REPORT_PREFIX, 0) != 0) {
        return std::make_pair(out, error::Env_AttestationFailure);
      }
      memcpy(out.data(), attestation.evidence().data() + strlen(SIMULATED_REPORT_PREFIX), out.size());
      return std::make_pair(out, error::OK);
    }
    return std::make_pair(out, error::General_Unimplemented);
  }

  // Given a string of size N, rewrite all bytes in that string with
  // random bytes.
  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    uint8_t* u8ptr = reinterpret_cast<uint8_t*>(bytes);
    if (simulated_) {
      while (size) {
        auto out = getrandom(u8ptr, size, 0);
        if (out < 0) {
          return error::Env_RandomBytes;
        }
        size -= out;
        u8ptr += out;
      }
    } else {
      // This may be slow but uses direct CPU instructions to get randomness.
      // We're not sure we can trust syscalls, as they might be sent up
      // to the hypervisor or the host OS, both of which we may not have fully
      // verified.
      unsigned long long r;
      uint8_t buf[8];
      CHECK(sizeof(r) == sizeof(buf));
      while (size) {
        if (1 != __builtin_ia32_rdrand64_step(&r)) {
          return error::Env_RandomBytes;
        }
        util::BigEndian64Bytes(r, buf);
        for (size_t i = 0; i < sizeof(buf) && size; i++) {
          *u8ptr++ = buf[i];
          size--;
        }
      }
    }
    return error::OK;
  }

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

  virtual void Init() {
    ::svr2::env::Environment::Init();
    if (simulated_) return;
    PublicKey k = {'i', 'n', 'i', 't', 0};
    enclaveconfig::RaftGroupConfig c;
    context::Context ctx;
    auto [attest, err] = Evidence(&ctx, k, c);
    std::stringstream sst;
    sst << "Evidence_err=" << err;
    Log(enclaveconfig::LOG_LEVEL_INFO, sst.str());
    CHECK(err == error::OK);
    // TODO: parse my own report to get my identity.
  }

 private:
  int32_t sev_fd_;
  bool simulated_;
};

}  // namespace
}  // namespace sev

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::sev::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
