// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "attestation/oe/attestation.h"

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/attestation/sgx/evidence.h>

#include <array>

#include "noise/noise.h"
#include "metrics/metrics.h"
#include "proto/error.pb.h"
#include "util/macros.h"

namespace svr2::attestation {
const oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
const oe_claim_t* FindClaim(const oe_claim_t* claims, size_t claims_size,
                            const char* name) {
  for (size_t i = 0; i < claims_size; i++) {
    if (strcmp(claims[i].name, name) == 0) return &(claims[i]);
  }
  return nullptr;
}

error::Error ReadKeyFromVerifiedClaims(oe_claim_t* claims, size_t claims_length,
                                       std::array<uint8_t, 32>& out) {
  const oe_claim_t* claim;
  oe_claim_t* custom_claims = nullptr;
  size_t custom_claims_length = 0;

  // read the custom claims
  if ((claim = FindClaim(claims, claims_length,
                         OE_CLAIM_CUSTOM_CLAIMS_BUFFER)) == nullptr) {
    return COUNTED_ERROR(Env_CustomClaimsMissing);
  }

  // deserialize custom claims
  if (oe_deserialize_custom_claims(claim->value, claim->value_size,
                                   &custom_claims,
                                   &custom_claims_length) != OE_OK) {
    return COUNTED_ERROR(Env_CustomClaimsDeserialize);
  }

  auto free_custom_claims_known_size = [custom_claims_length](oe_claim_t* ptr) {
    return oe_free_custom_claims(ptr, custom_claims_length);
  };
  std::unique_ptr<oe_claim_t, decltype(free_custom_claims_known_size)>
      free_custom_claims(custom_claims, free_custom_claims_known_size);

  // There is one custom claim with name "pk". The value is the key we will
  // return.
  if (strcmp(custom_claims[0].name, "pk") != 0) {
    return COUNTED_ERROR(Env_AttestationPubkeyMissing);
  }

  if (custom_claims[0].value_size != out.size()) {
    return COUNTED_ERROR(Env_AttestationPubkeyInvalidSize);
  }

  std::copy(custom_claims[0].value,
            custom_claims[0].value + custom_claims[0].value_size, out.begin());
  return error::OK;
}

std::pair<oe_claim_t*, size_t> VerifyAndReadClaims(
    const std::string& evidence, const std::string& endorsements) {
  const uint8_t* evidence_data =
      reinterpret_cast<const uint8_t*>(evidence.data());
  const uint8_t* endorsements_data =
      reinterpret_cast<const uint8_t*>(endorsements.data());
  oe_claim_t* claims = nullptr;
  size_t claims_length = 0;
  CHECK(OE_OK == oe_verify_evidence(&sgx_remote_uuid, evidence_data,
                                    evidence.size(), endorsements_data,
                                    endorsements.size(), nullptr, 0, &claims,
                                    &claims_length));

  return std::make_pair(claims, claims_length);
}

};  // namespace svr2::attestation
