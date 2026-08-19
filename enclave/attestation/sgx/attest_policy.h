// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_SGX_ATTEST_POLICY_H__
#define __SVR2_ATTESTATION_SGX_ATTEST_POLICY_H__

#include <stdint.h>
#include <string>

#include "proto/error.pb.h"

namespace svr2::attestation::sgx {

constexpr uint64_t kAttributeDebug = 0x1;
constexpr uint64_t kAttributeRemote = 0x2;

// OpenEnclave's required claims, as reported for a peer enclave.
struct PeerIdentity {
  std::string mrenclave;          // OE_CLAIM_UNIQUE_ID
  std::string signer_id;          // OE_CLAIM_SIGNER_ID
  std::string product_id;         // OE_CLAIM_PRODUCT_ID
  uint64_t attributes = 0;        // OE_CLAIM_ATTRIBUTES
  uint32_t security_version = 0;  // OE_CLAIM_SECURITY_VERSION
  uint32_t id_version = 0;        // OE_CLAIM_ID_VERSION
};

// Returns OK iff [actual] may be admitted to our replication group.  All peers
// are expected to be identical to us, so [expected] is our own identity.
error::Error CheckPeerIdentity(const PeerIdentity& actual,
                               const PeerIdentity& expected);

}  // namespace svr2::attestation::sgx

#endif  // __SVR2_ATTESTATION_SGX_ATTEST_POLICY_H__
