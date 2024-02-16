// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fts.h>
#include <time.h>

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
#include "proto/azuresnp.pb.h"
#include "queue/queue.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "util/mutex.h"
#include "util/endian.h"
#include "util/log.h"
#include "attestation/azuresnp/azuresnp.h"
#include "hmac/hmac.h"

namespace svr2::env {
namespace azuresnp {
namespace {

class Environment : public ::svr2::env::socket::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::socket::Environment(simulated) {}
  virtual ~Environment() {
  }
  // Attestation.evidence will be a serialization of attestation::azuresnp::ASNPEvidence.
  // Attestation.endorsements will be a serialization of attestation::azuresnp::ASNPEndorsements.
  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& data) const {
    if (simulated()) {
      return SimulatedEvidence(ctx, data);
    }
    e2e::Attestation out;
    auto evidence = ctx->Protobuf<attestation::azuresnp::ASNPEvidence>();
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

    LOG(DEBUG) << "Parsing out azuresnp-specific data from AttestationData";
    attestation::AttestationData out;
    auto evidence = ctx->Protobuf<attestation::azuresnp::ASNPEvidence>();
    auto endorsements = ctx->Protobuf<attestation::azuresnp::ASNPEndorsements>();
    if (!evidence->ParseFromString(attestation.evidence())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEvidence));
    }
    if (!endorsements->ParseFromString(attestation.endorsements())) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEndorsements));
    }

    LOG(DEBUG) << "Verifing that the provided AKCert is valid and verified by the SNP report and MSFT root of trust";
    if (auto err = attestation::azuresnp::VerifyAKCert(ctx, *evidence, *endorsements, now); err != error::OK) {
      return std::make_pair(out, err);
    }

    LOG(DEBUG) << "Verifing TPM2 quote";
    auto [sig, sigerr] = attestation::tpm2::Signature::FromString(evidence->sig());
    if (sigerr != error::OK) {
      return std::make_pair(out, sigerr);
    }
    auto [msg, msgerr] = attestation::tpm2::Report::FromString(evidence->msg());
    if (msgerr != error::OK) {
      return std::make_pair(out, msgerr);
    }
    attestation::tpm2::PCRs pcrs;
    if (auto err = attestation::tpm2::PCRsFromString(evidence->pcrs(), &pcrs); err != error::OK) {
      return std::make_pair(out, err);
    }
    auto akcert_start = reinterpret_cast<const uint8_t*>(evidence->akcert_der().data());
    bssl::UniquePtr<X509> akcert(d2i_X509(nullptr, &akcert_start, evidence->akcert_der().size()));
    if (!akcert) {
      return std::make_pair(out, COUNTED_ERROR(Env_ParseEvidence));
    } else if (auto err = sig.VerifyReport(msg, akcert.get()); err != error::OK) {
      return std::make_pair(out, err);
    } else if (auto err = msg.VerifyPCRs(pcrs); err != error::OK) {
      return std::make_pair(out, err);
    }

    LOG(DEBUG) << "Verifying remote PCRs against local ones";
    if (auto err = attestation::azuresnp::CheckRemotePCRs(ctx, local_pcrs_, pcrs); err != error::OK) {
      return std::make_pair(out, err);
    }

    LOG(DEBUG) << "Verifying that attestation data matches hash in TPM2 quote";
    if (auto ad_sha256 = hmac::Sha256(evidence->attestation_data()); !util::ConstantTimeEquals(ad_sha256, msg.nonce())) {
      return std::make_pair(out, COUNTED_ERROR(AzureSNP_AttestationDataHashMismatch));
    }

    if (!out.ParseFromString(evidence->attestation_data())) {
      return std::make_pair(std::move(out), COUNTED_ERROR(Env_ParseEvidence));
    }
    return std::make_pair(std::move(out), error::OK);
  }

  virtual error::Error UpdateEnvStats() const {
    return error::General_Unimplemented;
  }

  virtual void Init() {
    ::svr2::env::socket::Environment::Init();
    if (simulated()) { return; }
    auto [dir, direrr] = TempDir();
    if (direrr != error::OK) { LOG(FATAL) << "Creating temporary directory: " << direrr; }
    DirCleanup dc(dir);

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
    auto [azure_report, err1] = FileContents(dir + "/azure_report.bin");
    if (err1 != error::OK) { LOG(FATAL) << "File read failed"; }
    auto [akcert_der, err2] = FileContents(dir + "/akcert.der");
    if (err2 != error::OK) { LOG(FATAL) << "File read failed"; }
    auto [intermediate_der, err3] = FileContents(dir + "/intermediate.der");
    if (err3 != error::OK) { LOG(FATAL) << "File read failed"; }
    auto [vcek_der, err4] = FileContents(dir + "/vcek.der");
    if (err4 != error::OK) { LOG(FATAL) << "File read failed"; }
    auto [ask_der, err5] = FileContents(dir + "/ask.der");
    if (err5 != error::OK) { LOG(FATAL) << "File read failed"; }

    evidence_.set_azure_report(azure_report);
    evidence_.set_akcert_der(akcert_der);
    endorsements_.set_intermediate_der(intermediate_der);
    endorsements_.set_vcek_der(vcek_der);
    endorsements_.set_ask_der(ask_der);

    context::Context ctx;
    auto attestation_data = ctx.Protobuf<attestation::AttestationData>();
    auto tmp_evidence = ctx.Protobuf<attestation::azuresnp::ASNPEvidence>();
    if (auto err = CurrentEvidence(&ctx, *attestation_data, tmp_evidence)) {
      LOG(FATAL) << "Getting current evidence in Init: " << err;
    } else if (auto err = attestation::tpm2::PCRsFromString(tmp_evidence->pcrs(), &local_pcrs_)) {
      LOG(FATAL) << "Loading local PCRs: " << err;
    }
    for (size_t i = 0; i < local_pcrs_.size(); i++) {
      LOG(DEBUG) << "PCRS[" << i << "]: " << util::ToHex(local_pcrs_[i]);
    }

    if (auto [attestation, err] = Evidence(&ctx, *attestation_data); err != error::OK) {
      LOG(FATAL) << "Failure to get evidence in Init: " << err;
    } else if (auto [data, err] = Attest(&ctx, time(nullptr), attestation); err != error::OK) {
      LOG(FATAL) << "Failure to attest evidence in Init: " << err;
    }
    LOG(INFO) << "Successfully retrieved and attested evidence";
  }
 
 private:
  class DirCleanup {
   public:
    DirCleanup(const std::string& name) : name_(name) {}
    ~DirCleanup() {
      LOG(DEBUG) << "Recursively deleting directory " << name_;
      const char* files[] = {name_.c_str(), nullptr};
      FTS* fts = fts_open(const_cast<char *const *>(files), FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
      if (!fts) {
        LOG(ERROR) << "Error recursively deleting '" << name_ << "'";
        return;
      }
      FTSENT* curr;
      while (nullptr != (curr = fts_read(fts))) {
        switch (curr->fts_info) {
          case FTS_D:  // directory, in pre-order
            break;
          case FTS_DP:  // directory, in post-order
          case FTS_F:   // normal file
            LOG(DEBUG) << " rm " << curr->fts_accpath;
            if (int ret = remove(curr->fts_accpath); ret != 0) {
              LOG(ERROR) << "Error deleting file '" << curr->fts_accpath << "' in temp directory '" << name_ << "': " << strerror(errno);
            }
            break;
          default:
            LOG(ERROR) << "Unable to handle deletion of file '" << curr->fts_accpath << "' in temp directory '" << name_ << "'";
        }
      }
    }
   private:
    std::string name_;
  };

  std::pair<std::string, error::Error> TempDir() const {
    std::array<uint8_t, 8> bytes;
    if (auto err = RandomBytes(bytes.data(), bytes.size()); err != error::OK) {
      return std::make_pair("", err);
    }
    std::string name = "/tmp/svr." + util::ToHex(bytes);
    if (int ret = mkdir(name.c_str(), 0700); ret != 0) {
      LOG(ERROR) << "Making temp directory failed: " << strerror(errno);
      return std::make_pair("", COUNTED_ERROR(AzureSNP_Mkdir));
    }
    LOG(DEBUG) << "New temp directory: " << name;
    return std::make_pair(name, error::OK);
  }

  std::pair<std::string, error::Error> FileContents(const std::string& filename) const {
    int fd = open(filename.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd <= 0) {
      LOG(ERROR) << "Opening file '" << filename << "' for read: " << strerror(errno);
      return std::make_pair("", COUNTED_ERROR(AzureSNP_OpenFile));
    }
    char buf[64];
    ssize_t ret = -1;
    std::string out;
    while (0 < (ret = read(fd, buf, sizeof(buf)))) {
      out.append(buf, static_cast<size_t>(ret));
    }
    if (ret < 0) {
      LOG(ERROR) << "Reading file '" << filename << "': " << strerror(errno);
      close(fd);
      return std::make_pair("", COUNTED_ERROR(AzureSNP_OpenFile));
    }
    close(fd);
    return std::make_pair(std::move(out), error::OK);
  }

  error::Error CurrentEvidence(context::Context* ctx, const attestation::AttestationData& data, attestation::azuresnp::ASNPEvidence* evidence) const {
    std::string serialized = data.SerializeAsString();
    auto attestation_data_sha256 = hmac::Sha256(serialized);

    auto [dir, direrr] = TempDir();
    RETURN_IF_ERROR(direrr);
    DirCleanup dc(dir);

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
    auto [msg, err1] = FileContents(dir + "/msg");
    RETURN_IF_ERROR(err1);
    auto [sig, err2] = FileContents(dir + "/sig");
    RETURN_IF_ERROR(err2);
    auto [pcrs, err3] = FileContents(dir + "/pcrs");
    RETURN_IF_ERROR(err3);

    evidence->MergeFrom(evidence_);
    evidence->set_attestation_data(serialized);
    evidence->set_pcrs(pcrs);
    evidence->set_msg(msg);
    evidence->set_sig(sig);
    return error::OK;
  }

  attestation::azuresnp::ASNPEvidence evidence_;
  attestation::azuresnp::ASNPEndorsements endorsements_;
  attestation::tpm2::PCRs local_pcrs_;
};

}  // namespace
}  // namespace azuresnp

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::azuresnp::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
