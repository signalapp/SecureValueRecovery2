// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_ATTESTATION_H__
#define __SVR2_ATTESTATION_ATTESTATION_H__

#include <array>

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>

#include "proto/error.pb.h"


namespace svr2::attestation {
  
extern const oe_uuid_t sgx_remote_uuid;

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
const oe_claim_t* FindClaim(const oe_claim_t* claims, size_t claims_size,
                            const char* name);
/**
 * Deserializes Open Enclave format custom claims then finds, validates,
 * and returns the public key claim.
 *
 * claims serialized OpenEnclave claims
 * claims_length number of claims
 * out: array where public key will be written
 * returns Env_CustomClaimsMissing, Env_CustomClaimsDeserialize,
 *     Env_AttestationPubkeyMissing, Env_AttestationPubkeyInvalidSize
 */
error::Error ReadKeyFromVerifiedClaims(oe_claim_t* claims, size_t claims_length,
                                       std::array<uint8_t, 32>* out);

/**
 * Verifies evidence and endorsements and returns the parsed array
 * of claims in Open Enclave format.
 * 
 * The returned pointer most be freed with `oe_free_claims`
 */
std::pair<oe_claim_t*, size_t> VerifyAndReadClaims(
    const std::string& evidence, const std::string& endorsements);

};  // namespace svr2::attestation


#endif  // __SVR2_ATTESTATION_ATTESTATION_H__
