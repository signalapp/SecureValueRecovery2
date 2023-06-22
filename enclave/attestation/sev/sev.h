// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_SEV_SEV_H__
#define __SVR2_ATTESTATION_SEV_SEV_H__

#include <string>
#include <stdint.h>
#include "proto/error.pb.h"
#include "proto/sev.pb.h"
#include "env/env.h"
#include "util/ticks.h"

namespace svr2::attestation::sev {

#include <attestation.h>

// Read in an SevSnpEndorsements proto from the file with the given filename.
// Returns true if this is successful, false on error.
bool EndorsementsFromFile(const char* filename, SevSnpEndorsements* endorsements);

// CertificatesToEndorsements parses certificates provided via SNP_GET_EXT_REPORT.
// If it finds any, it overwrites the *endorsements fields with what it finds.
error::Error CertificatesToEndorsements(const uint8_t* certs, uint32_t certs_size, SevSnpEndorsements* endorsements);

// Pulls an SEV-SNP attestation report from the given attestation object,
// without doing any crypto verification.
std::pair<attestation_report, error::Error> ReportFromUnverifiedAttestation(const e2e::Attestation& attestation);

// Pulls a public key from the given attestation, verifying that attestation
// as much as possible in the process.  Will return an error if the attestation
// is invalid, does not match the given local attestation in the necessary ways,
// or does not verify against known AMD public keys.
std::pair<env::PublicKey, error::Error> KeyFromVerifiedAttestation(const attestation_report& local, const e2e::Attestation& attestation, util::UnixSecs now);

}  // namespace svr2::attestation::sev

#endif  // __SVR2_ATTESTATION_SEV_SEV_H__
