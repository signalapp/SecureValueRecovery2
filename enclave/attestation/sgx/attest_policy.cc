// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "attestation/sgx/attest_policy.h"

#include "metrics/metrics.h"
#include "util/constant.h"

namespace svr2::attestation::sgx {

error::Error CheckPeerIdentity(const PeerIdentity& actual,
                               const PeerIdentity& expected) {
  // Fail closed if we never derived our own identity.
  if (expected.mrenclave.empty()) {
    return COUNTED_ERROR(Env_MissingMRENCLAVE);
  }
  if (expected.signer_id.empty()) {
    return COUNTED_ERROR(AttestationSGX_MissingSignerId);
  }
  if (expected.product_id.empty()) {
    return COUNTED_ERROR(AttestationSGX_MissingProductId);
  }

  if (actual.id_version != expected.id_version) {
    return COUNTED_ERROR(AttestationSGX_WrongIdVersion);
  }
  if (!util::ConstantTimeEquals(actual.mrenclave, expected.mrenclave)) {
    return COUNTED_ERROR(Env_WrongMRENCLAVE);
  }
  if (!util::ConstantTimeEquals(actual.signer_id, expected.signer_id)) {
    return COUNTED_ERROR(AttestationSGX_WrongSignerId);
  }
  if (!util::ConstantTimeEquals(actual.product_id, expected.product_id)) {
    return COUNTED_ERROR(AttestationSGX_WrongProductId);
  }
  if (actual.security_version != expected.security_version) {
    return COUNTED_ERROR(AttestationSGX_WrongSecurityVersion);
  }
  // Rejected outright rather than self-derived, so that a debug build can
  // never bootstrap a debug group.
  // Note that when we use `simulated` enclaves, the env code tends to skip
  // this stuff, hence allowing tests based on simulated enclaves to succeed.
  if (actual.attributes & kAttributeDebug) {
    return COUNTED_ERROR(AttestationSGX_DebugEnabled);
  } else if (!(actual.attributes & kAttributeRemote)) {
    return COUNTED_ERROR(AttestationSGX_RemoteCapable);
  }
  return error::OK;
}

}  // namespace svr2::attestation::sgx
