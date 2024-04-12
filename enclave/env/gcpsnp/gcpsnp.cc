// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sstream>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium/crypto_hash_sha256.h>
#include <openssl/x509.h>

#include "attestation/sev/sev.h"
#include "attestation/tpm2snp/tpm2snp.h"
#include "env/env.h"
#include "env/socket/socket.h"
#include "sevtypes/sevtypes.h"
#include "util/macros.h"
#include "util/constant.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "proto/tpm2snp.pb.h"
#include "proto/sev.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/mutex.h"
#include "util/endian.h"
#include "util/base64.h"
#include "util/log.h"
#include "hmac/hmac.h"
#include "fs/fs.h"

namespace svr2::env {
namespace gcpsnp {
namespace {

class Environment : public ::svr2::env::socket::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::socket::Environment(simulated) {
  }
  virtual ~Environment() {
  }

  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    if (simulated()) {
      return SimulatedEvidence(ctx, data);
    }

    e2e::Attestation out;
    std::string serialized;
    if (!data.SerializeToString(&serialized)) {
      return std::make_pair(out, error::Env_SerializeAttestationData);
    }
    auto hash = hmac::Sha256(serialized);
    auto current_evidence = ctx->Protobuf<attestation::tpm2snp::TPM2SNPEvidence>();
    if (auto err = GcpEvidenceAndEndorsements(hash, current_evidence, nullptr); err != error::OK) {
      return std::make_pair(out, err);
    }
    auto merged_evidence = ctx->Protobuf<attestation::tpm2snp::TPM2SNPEvidence>();
    merged_evidence->MergeFrom(base_evidence_);
    merged_evidence->MergeFrom(*current_evidence);
    merged_evidence->set_attestation_data(serialized);
    if (!merged_evidence->SerializeToString(out.mutable_evidence())) {
      return std::make_pair(out, error::GCPSNP_SerializeEvidence);
    }
    if (!base_endorsements_.SerializeToString(out.mutable_endorsements())) {
      return std::make_pair(out, error::GCPSNP_SerializeEndorsements);
    }
    return std::make_pair(out, error::OK);
  }

  // Given evidence and endorsements, extract the key.
  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    if (simulated()) {
      return SimulatedAttest(ctx, now, attestation);
    }
    attestation::AttestationData out;
    LOG(DEBUG) << "Parsing attestation evidence and endorsements";
    auto evidence = ctx->Protobuf<attestation::tpm2snp::TPM2SNPEvidence>();
    auto endorsements = ctx->Protobuf<attestation::tpm2snp::TPM2SNPEndorsements>();
    if (!evidence->ParseFromString(attestation.evidence())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEvidence));
    }
    if (!endorsements->ParseFromString(attestation.endorsements())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEndorsements));
    }

    return attestation::tpm2snp::CompleteVerification(ctx, *evidence, *endorsements, now, attestation::tpm2snp::gcp_roots_of_trust, local_pcrs_);
  }

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

  virtual void Init() {
    ::svr2::env::Environment::Init();
    if (simulated()) return;
    context::Context ctx;

    std::array<uint8_t, 32> nonce;
    if (auto err = GcpEvidenceAndEndorsements(nonce, &base_evidence_, &base_endorsements_); err != error::OK) {
      LOG(FATAL) << "Failed GcpEvidenceAndEndorsements during Init: " << err;
    }
    auto akcert_start = reinterpret_cast<const uint8_t*>(base_evidence_.akcert_der().data());
    bssl::UniquePtr<X509> akcert(d2i_X509(nullptr, &akcert_start, base_evidence_.akcert_der().size()));
    if (!akcert) {
      LOG(FATAL) << "Invalid AKCert DER";
    }
    auto [azure_runtime_data, azrerr] = attestation::tpm2snp::AzureRuntimeDataFromCert(akcert.get());
    if (azrerr != error::OK) {
      LOG(FATAL) << "Unable to create Azure runtime data from AK cert: " << azrerr;
    }
    base_evidence_.set_runtime_data(azure_runtime_data);
    auto runtime_hash = hmac::Sha256(azure_runtime_data);

    attestation::sev::SevSnpEndorsements sev_endorsements;

    std::string snp_report;
    if (auto err = SnpReport(&ctx, runtime_hash, &snp_report, &sev_endorsements); err != error::OK) {
      LOG(FATAL) << "Unable to get SNP report: " << err;
    }
    base_endorsements_.set_vcek_der(sev_endorsements.vcek_der());
    base_endorsements_.set_ask_der(sev_endorsements.ask_der());
    LOG(INFO) << "SNP report size: " << snp_report.size();
    base_evidence_.set_snp_report(snp_report);

    if (auto err = attestation::tpm2::PCRsFromString(base_evidence_.pcrs(), &local_pcrs_); err != error::OK) {
      LOG(FATAL) << "Failure to parse PCRs from base evidence: " << err;
    }
    for (size_t i = 0; i < local_pcrs_.size(); i++) {
      LOG(INFO) << "PCRs[" << i << "]: " << util::ToHex(local_pcrs_[i]);
    }

    attestation::AttestationData attestation_data;
    if (auto [attestation, err] = Evidence(&ctx, attestation_data); err != error::OK) {
      LOG(FATAL) << "Failure to get evidence in Init: " << err;
    } else if (auto [data, err] = Attest(&ctx, time(nullptr), attestation); err != error::OK) {
      LOG(FATAL) << "Failure to attest evidence in Init: " << err;
    }
    LOG(INFO) << "Base evidence and endorsements created successfully";
    if (auto [elog, err] = fs::FileContents("/sys/kernel/security/tpm0/binary_bios_measurements"); err != error::OK) {
      LOG(ERROR) << "Unable to retrieve event log: " << err;
    } else {
      LOG(INFO) << "Event log: " << util::Base64Encode(elog, util::B64STD, true);
    }
  }

 private:
  error::Error GcpEvidenceAndEndorsements(
      const std::array<uint8_t, 32>& nonce,
      attestation::tpm2snp::TPM2SNPEvidence* evidence,
      attestation::tpm2snp::TPM2SNPEndorsements* endorsements) const {
    fs::TmpDir tmpdir;
    RETURN_IF_ERROR(tmpdir.Init());
    std::string cmd = "/usr/bin/svr3gcp --debug=false --nonce_hex=" + util::ToHex(nonce);
    std::string evidence_proto_file = tmpdir.name() + "/evidence_proto_file";
    std::string endorsements_proto_file = tmpdir.name() + "/endorsements_proto_file";
    if (evidence) { cmd.append(" --evidence_output=" + evidence_proto_file); }
    if (endorsements) { cmd.append(" --endorsements_output=" + endorsements_proto_file); }
    LOG(INFO) << "Running cmd: " << cmd;
    if (int ret = system(cmd.c_str()); ret != 0) {
      return COUNTED_ERROR(GCPSNP_RunEvidenceEndorsementsBinary);
    }
    if (evidence) {
      auto [evidence_proto, err] = fs::FileContents(evidence_proto_file);
      RETURN_IF_ERROR(err);
      if (!evidence->ParseFromString(evidence_proto)) {
        return COUNTED_ERROR(GCPSNP_ParseEvidenceProtoFile);
      }
    }
    if (endorsements) {
      auto [endorsements_proto, err] = fs::FileContents(endorsements_proto_file);
      RETURN_IF_ERROR(err);
      if (!endorsements->ParseFromString(endorsements_proto)) {
        return COUNTED_ERROR(GCPSNP_ParseEndorsementsProtoFile);
      }
    }
    return error::OK;
  }

  error::Error SnpReport(
      context::Context* ctx,
      std::array<uint8_t, 32> nonce,
      std::string* report,
      attestation::sev::SevSnpEndorsements* endorsements) const {
    // Make the request
    snp_ext_report_req req;
    snp_report_resp resp;
    snp_guest_request_ioctl guest_req;
    attestation::sev::msg_report_resp* report_resp = reinterpret_cast<attestation::sev::msg_report_resp*>(&resp.data);
    uint8_t certs[SEV_FW_BLOB_MAX_SIZE];
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(&guest_req, 0, sizeof(guest_req));
    memset(certs, 0, sizeof(certs));
    req.certs_address = reinterpret_cast<__u64>(&certs[0]);
    req.certs_len = sizeof(certs);

    CHECK(sizeof(req.data.user_data) >= nonce.size());
    memcpy(req.data.user_data, nonce.data(), nonce.size());

    guest_req.msg_version = 1;
    guest_req.req_data = reinterpret_cast<__u64>(&req);
    guest_req.resp_data = reinterpret_cast<__u64>(&resp);

    LOG(INFO) << "Opening SEV device";
    int sev_fd = 0;
    for (const char* devname : {"/dev/sev-guest", "/dev/sev"}) {
      sev_fd = open(devname, O_RDWR | O_CLOEXEC);
      if (sev_fd > 0) break;
      LOG(WARNING) << "Failed to open SEV device: " << devname;
    }
    CHECK(sev_fd > 0);
    int ioctl_ret = ioctl(sev_fd, SNP_GET_EXT_REPORT, &guest_req);
    {
      auto e = errno;
      LOG(DEBUG) << "SEV_IOCTL OUTPUT:"
          << " ioctl_ret=" << ioctl_ret
          << " fw_error=" << guest_req.fw_error
          << " vmm_error=" << guest_req.vmm_error
          << " status=" << report_resp->status
          << " errno_str=" << strerror(e);
    }
    LOG(INFO) << "Closing SEV device";
    close(sev_fd);

    if (ioctl_ret < 0) {
      return COUNTED_ERROR(Sev_ReportIOCTLFailure);
    } else if (0 != guest_req.fw_error || 0 != guest_req.vmm_error || 0 != report_resp->status) {
      return COUNTED_ERROR(Sev_FirmwareError);
    } else if (sizeof(report_resp->report) != report_resp->report_size) {
      return COUNTED_ERROR(Sev_ReportSizeMismatch);
    } else if (auto err = attestation::sev::CertificatesToEndorsements(certs, req.certs_len, endorsements); err != error::OK) {
      return err;
    }
    LOG(INFO) << report_resp->report;
    report->resize(sizeof(report_resp->report));
    memcpy(report->data(), reinterpret_cast<const char*>(&report_resp->report), sizeof(report_resp->report));
    return error::OK;
  }

  attestation::tpm2snp::TPM2SNPEvidence base_evidence_;
  attestation::tpm2snp::TPM2SNPEndorsements base_endorsements_;
  attestation::tpm2::PCRs local_pcrs_;
};

}  // namespace
}  // namespace gcpsnp

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::gcpsnp::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
