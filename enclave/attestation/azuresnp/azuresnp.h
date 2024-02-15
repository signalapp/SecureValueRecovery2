// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_AZURESNP_AZURESNP_H__
#define __SVR2_ATTESTATION_AZURESNP_AZURESNP_H__

#include "proto/azuresnp.pb.h"
#include "proto/error.pb.h"
#include "attestation/tpm2/tpm2.h"
#include "context/context.h"
#include "util/ticks.h"

namespace svr2::attestation::azuresnp {

// Azure confidential computing allows for the use of AMD SEV-SNP (herafter
// AMDSNP) protection for its computation.  AMDSNP measures the boot state
// of a (running) container and provides a cryptographic proof of that
// state rooted at AMD (via an X509 chain).  An AMDSNP report specifically
// measures the firmware used to run a container.  However, Azure does not
// open-source its firmware, and may regularly or without notice update the
// firmware across its fleet.  Therefore, it uses a combination of AMDSNP
// and a TPM2 set of PCRs to provide trust that's rooted at MSFT+AMD, not
// just AMD (herafter AzSNP).  It does this by:
//
// - running firmware vetted by MSFT, and after vetting providing an
//   AKCert to that firmware's TPM2 module
// - generating, on boot and after firmware vetting, an AMDSNP report that
//   contains a `report_data` including the publick key of that AKCert
// - using TPM2 PCRs in the normal manner to measure the boot process,
//   kernel, kernel cmd line, etc.
//
// To use this AzSNP verification, then, we must:
//
// - verify the SNP report is valid (but not look at its measurement,
//   since we have no basis for checking its validity)
// - check that the TPM2 has an AKCert that roots to MSFT's root-of-trust
// - checking that the SNP report contains a guarantee of the public key
//   used by the AKCert
// - getting a TPM2 quote of PCRs using the AKCert
//
// This, in short, gives us verification of the AMD chip/microcode
// (via the SNP report), firmware (via rooting of the AKCert in a MSFT
// trust root), and kernel/cmd-line/boot-process (via TPM2 PCRs).
// To verify up to the application layer, we must go further to tie
// the kernel/cmdline to the appication layer, which we initially do
// via dm-verity, allowing us to verify the disk image hash within the
// kernel cmdline.

// Given the azure TPM2 buffer, extract the SNP report buffer from it.
std::pair<std::string, error::Error> SNPReportBufferFromAzureBuffer(const std::string& tpm2_buffer);
// Given the azure TPM2 buffer, extract the runtime report that's hashed
// into snp_report.report_data from it.
std::pair<std::string, error::Error> RuntimeDataBufferFromAzureBuffer(const std::string& tpm2_buffer);

// Verifies that the AK certificate in `evidence` is rooted in the
// known MSFT root-of-trust and is correctly contained by the SNP
// report in `evidence`.  This verification includes:
// - verifying that evidence.akcert_der is valid
// - verifying that endorsements.intermediate_der is valid
// - verifying that evidence.akcert_der and endorsements.intermediate_der are
//   part of a currently-valid certificate chain up to the MSFT root-of-trust
// - verifying that evidence.azure_report's SNP report is valid
// - verifying that evidence.azure_report's SNP report's report_data contains
//   a SHA256 of evidence.azure_report's runtime data
// - verifying that evidence.azure_report's runtime data contains the public
//   key contained within evidence.akcert_der (RSA `n` and `e` match)
error::Error VerifyAKCert(context::Context* ctx, const ASNPEvidence& evidence, const ASNPEndorsements& endorsements, util::UnixSecs now);

// Given a set of PCRs for the local machine and a set of PCRs for
// a potential remote peer, verify that the potential peer's PCRs are
// allowable and we should move forward with the trusted connection.
error::Error CheckRemotePCRs(context::Context* ctx, const attestation::tpm2::PCRs& local, const attestation::tpm2::PCRs& remote);

}  // namespace svr2::attestation::azuresnp

#endif  // __SVR2_ATTESTATION_AZURESNP_AZURESNP_H__
