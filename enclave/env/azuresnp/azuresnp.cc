// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <unistd.h>

#include "attestation/sev/sev.h"
#include "attestation/tpm2/tpm2.h"
#include "env/env.h"
#include "env/socket/socket.h"
#include "sevtypes/sevtypes.h"
#include "util/macros.h"
#include "util/constant.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "proto/sev.pb.h"
#include "proto/tpm2snp.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/mutex.h"
#include "util/endian.h"
#include "util/log.h"
#include "attestation/tpm2snp/tpm2snp.h"
#include "hmac/hmac.h"
#include "fs/fs.h"

namespace svr2::env {
namespace azuresnp {
namespace {

class Environment : public ::svr2::env::socket::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::socket::Environment(simulated) {}
  virtual ~Environment() {
  }
  // Attestation.evidence will be a serialization of attestation::tpm2snp::ASNPEvidence.
  // Attestation.endorsements will be a serialization of attestation::tpm2snp::ASNPEndorsements.
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const {
    if (simulated()) {
      return SimulatedEvidence(ctx, data);
    }
    e2e::Attestation out;
    auto evidence = ctx->Protobuf<attestation::tpm2snp::ASNPEvidence>();
    if (auto err = CurrentEvidence(ctx, data, evidence); err != error::OK) {
      return std::make_pair(out, err);
    }
    if (!evidence->SerializeToString(out.mutable_evidence())) {
      LOG(ERROR) << "Failed to serialize evidence";
      return std::make_pair(std::move(out), COUNTED_ERROR(Env_GetEvidence));
    }
    if (!endorsements_.SerializeToString(out.mutable_endorsements())) {
      LOG(ERROR) << "Failed to serialize endorsements";
      return std::make_pair(std::move(out), COUNTED_ERROR(Env_GetEvidence));
    }
    return std::make_pair(std::move(out), error::OK);
  }

  // Given evidence and endorsements, extract the key.
  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    if (simulated()) {
      return SimulatedAttest(ctx, now, attestation);
    }

    attestation::AttestationData out;
    auto evidence = ctx->Protobuf<attestation::tpm2snp::ASNPEvidence>();
    auto endorsements = ctx->Protobuf<attestation::tpm2snp::ASNPEndorsements>();
    if (!evidence->ParseFromString(attestation.evidence())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEvidence));
    }
    if (!endorsements->ParseFromString(attestation.endorsements())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEndorsements));
    }

    LOG(DEBUG) << "Parsing out azuresnp-specific data from AttestationData";
    return attestation::tpm2snp::CompleteVerification(ctx, *evidence, *endorsements, now, attestation::tpm2snp::azure_roots_of_trust, local_pcrs_);
  }

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

  virtual void Init() {
    ::svr2::env::socket::Environment::Init();
    if (simulated()) { return; }
    fs::TmpDir tmpdir;
    if (auto err = tmpdir.Init(); err != error::OK) {
      LOG(FATAL) << "Creating temporary directory: " << err;
    }
    auto dir = tmpdir.name();

    // Gather some information from the system by running various commands,
    // and apply it to `evidence_` and `endorsements_`.  These are all
    // information that will not change through the lifetime of the process.
    for (std::string cmd : {
        // Read in Azure-specific report (containing SNP report and runtime data)
        "/usr/bin/tpm2_nvread -C o 0x01400001 --output " + dir + "/azure_report.bin",
        // Read in the TPM2 AK key certificate (key is at 0x81000003, which is used when we tpm2_quote)
        "/usr/bin/tpm2_nvread -C o 0x1C101D0 -o " + dir + "/akcert.der",
        // Read in intermediate cert between TPM2 AK cert and MSFT root-of-trust (which we compile in).
        // TODO: grab the intermediate cert locally, rather than from MSFT.  The plan to do this
        //       is to serve them from a local nginx service within the replica's region
        "/usr/bin/curl --silent 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq?tabs=cli%2Cdebianbased#certificates' | grep -A32 'intermediate CA' | grep -v '<' > " + dir + "/intermediate.pem",
        // Grab instance-specific VCEK and chain.
        "/usr/bin/curl --silent -H Metadata:true http://169.254.169.254/metadata/THIM/amd/certification -o " + dir + "/vcek",
        "/usr/bin/jq -r .vcekCert " + dir + "/vcek > " + dir + "/vcek.pem",
        "/usr/bin/jq -r .certificateChain " + dir + "/vcek > " + dir + "/vcek_chain.pem",
        // Convert VCEK certificate's PEM to DER
        "/usr/bin/openssl x509 -in " + dir + "/vcek.pem -inform PEM -out " + dir + "/vcek.der -outform DER",
        // Convert VCEK_CHAIN first certificate's PEM to DER.  The first cert in the chain is the ASK, which is what we want.
        "/usr/bin/openssl x509 -in " + dir + "/vcek_chain.pem -inform PEM -out " + dir + "/ask.der -outform DER",
        // Convert the intermediate certificate's PEM to DER
        "/usr/bin/openssl x509 -in " + dir + "/intermediate.pem -inform PEM -out " + dir + "/intermediate.der -outform DER",
    }) {
      LOG(INFO) << "Running command: " << cmd;
      bool success = false;
      // Retry a few times over a total of ~2-3 minutes.
      // It appears that the TPM may need some "warm-up time" before it gets
      // all of its stuff in order.
      for (int i = 0; i < 6; i++) {
        int ret = system(cmd.c_str());
        if (ret == 0) {
          success = true;
          break;
        }
        LOG(ERROR) << "Command failed, retrying again in " << (1 << i) << " seconds, failure=" << ret;
        sleep(1 << i);
      }
      if (!success) {
        LOG(FATAL) << "Command " << cmd << " failed after multiple attempts";
      }
    }
    auto [azure_report, err1] = fs::FileContents(dir + "/azure_report.bin");
    if (err1 != error::OK) { LOG(FATAL) << "File read failed: " << err1; }
    auto [akcert_der, err2] = fs::FileContents(dir + "/akcert.der");
    if (err2 != error::OK) { LOG(FATAL) << "File read failed: " << err2; }
    auto [intermediate_der, err3] = fs::FileContents(dir + "/intermediate.der");
    if (err3 != error::OK) { LOG(FATAL) << "File read failed: " << err3; }
    auto [vcek_der, err4] = fs::FileContents(dir + "/vcek.der");
    if (err4 != error::OK) { LOG(FATAL) << "File read failed: " << err4; }
    auto [ask_der, err5] = fs::FileContents(dir + "/ask.der");
    if (err5 != error::OK) { LOG(FATAL) << "File read failed: " << err5; }

    auto [snp_report, err6] = attestation::tpm2snp::SNPReportBufferFromAzureBuffer(azure_report);
    if (err6 != error::OK) { LOG(FATAL) << "SNPReportBufferFromAzureBuffer failed: " << err6; }
    auto [runtime_data, err7] = attestation::tpm2snp::RuntimeDataBufferFromAzureBuffer(azure_report);
    if (err7 != error::OK) { LOG(FATAL) << "RuntimeDataBufferFromAzureBuffer failed: " << err7; }
    evidence_.set_snp_report(snp_report);
    evidence_.set_runtime_data(runtime_data);
    evidence_.set_akcert_der(akcert_der);
    endorsements_.set_intermediate_der(intermediate_der);
    endorsements_.set_vcek_der(vcek_der);
    endorsements_.set_ask_der(ask_der);

    context::Context ctx;
    auto attestation_data = ctx.Protobuf<attestation::AttestationData>();
    auto tmp_evidence = ctx.Protobuf<attestation::tpm2snp::ASNPEvidence>();
    if (auto err = CurrentEvidence(&ctx, *attestation_data, tmp_evidence)) {
      LOG(FATAL) << "Getting current evidence in Init: " << err;
    } else if (auto err = attestation::tpm2::PCRsFromString(tmp_evidence->pcrs(), &local_pcrs_)) {
      LOG(FATAL) << "Loading local PCRs: " << err;
    }
    for (size_t i = 0; i < local_pcrs_.size(); i++) {
      LOG(INFO) << "PCRS[" << i << "]: " << util::ToHex(local_pcrs_[i]);
    }

    if (auto [attestation, err] = Evidence(&ctx, *attestation_data); err != error::OK) {
      LOG(FATAL) << "Failure to get evidence in Init: " << err;
    } else if (auto [data, err] = Attest(&ctx, time(nullptr), attestation); err != error::OK) {
      LOG(FATAL) << "Failure to attest evidence in Init: " << err;
    }
    LOG(INFO) << "Successfully retrieved and attested evidence";
  }
 
 private:
  error::Error CurrentEvidence(context::Context* ctx, const attestation::AttestationData& data, attestation::tpm2snp::ASNPEvidence* evidence) const {
    std::string serialized = data.SerializeAsString();
    auto attestation_data_sha256 = hmac::Sha256(serialized);

    fs::TmpDir tmpdir;
    RETURN_IF_ERROR(tmpdir.Init());
    auto dir = tmpdir.name();

    std::string cmd = (
        "/usr/bin/tpm2_quote"
        // Quote using the TPM's AK key
        " -c 0x81000003"
        // Add the SHA256 of the attestation data's serialized form into the quote
        " -q " + util::ToHex(attestation_data_sha256) +
        // Output msg, sig, and PCRs to our temporary directory
        " -m " + dir + "/msg"
        " -s " + dir + "/sig"
        " -o " + dir + "/pcrs"
        // Output all PCRs as concatenated SHA256 (24 PCRs * 32 bytes = 768 bytes total)
        " -l sha256:all"
        " --pcrs_format values"
        // Ignore STDOUT
        " >/dev/null");
    LOG(DEBUG) << "Running command: " << cmd;
    if (int ret = system(cmd.c_str()); ret != 0) {
      LOG(ERROR) << "Command to get attestation data (" << cmd << ") failed: " << ret;
      return COUNTED_ERROR(Env_GetEvidence);
    }
    auto [msg, err1] = fs::FileContents(dir + "/msg");
    RETURN_IF_ERROR(err1);
    auto [sig, err2] = fs::FileContents(dir + "/sig");
    RETURN_IF_ERROR(err2);
    auto [pcrs, err3] = fs::FileContents(dir + "/pcrs");
    RETURN_IF_ERROR(err3);

    evidence->MergeFrom(evidence_);
    evidence->set_attestation_data(serialized);
    evidence->set_pcrs(pcrs);
    evidence->set_msg(msg);
    evidence->set_sig(sig);
    return error::OK;
  }

  attestation::tpm2snp::ASNPEvidence evidence_;
  attestation::tpm2snp::ASNPEndorsements endorsements_;
  attestation::tpm2::PCRs local_pcrs_;
};

}  // namespace
}  // namespace azuresnp

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::azuresnp::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
