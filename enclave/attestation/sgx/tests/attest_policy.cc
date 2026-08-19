// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP env
//TESTDEP env/test
//TESTDEP util
//TESTDEP gtest
//TESTDEP proto
//TESTDEP context
//TESTDEP metrics
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>

#include <string>

#include "attestation/sgx/attest_policy.h"
#include "env/env.h"

namespace svr2::attestation::sgx {

class AttestPolicyTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { env::Init(env::SIMULATED); }

  // OE_REPORT_ATTRIBUTES_REMOTE (0x2) is set on all remote attestations.
  PeerIdentity Identity() const {
    PeerIdentity id;
    id.mrenclave = std::string(32, '\xaa');
    id.signer_id = std::string(32, '\xbb');
    id.product_id = std::string(16, '\xcc');
    id.attributes = 0x2;
    id.security_version = 1;
    id.id_version = 0;
    return id;
  }

  error::Error Check(const PeerIdentity& p) const {
    return CheckPeerIdentity(p, Identity());
  }
};

TEST_F(AttestPolicyTest, AcceptsMatchingIdentity) {
  ASSERT_EQ(error::OK, Check(Identity()));
}

TEST_F(AttestPolicyTest, RejectsWrongMRENCLAVE) {
  auto p = Identity();
  p.mrenclave = std::string(32, '\xee');
  ASSERT_EQ(error::Env_WrongMRENCLAVE, Check(p));
}

TEST_F(AttestPolicyTest, RejectsWrongSignerId) {
  auto p = Identity();
  p.signer_id = std::string(32, '\xee');
  ASSERT_EQ(error::AttestationSGX_WrongSignerId, Check(p));
}

TEST_F(AttestPolicyTest, RejectsWrongProductId) {
  auto p = Identity();
  p.product_id = std::string(16, '\xee');
  ASSERT_EQ(error::AttestationSGX_WrongProductId, Check(p));
}

TEST_F(AttestPolicyTest, RejectsWrongSecurityVersion) {
  auto p = Identity();
  p.security_version = 2;
  ASSERT_EQ(error::AttestationSGX_WrongSecurityVersion, Check(p));
}

TEST_F(AttestPolicyTest, RejectsWrongIdVersion) {
  auto p = Identity();
  p.id_version = 1;
  ASSERT_EQ(error::AttestationSGX_WrongIdVersion, Check(p));
}

TEST_F(AttestPolicyTest, RejectsDebugAttribute) {
  auto p = Identity();
  p.attributes |= kAttributeDebug;
  ASSERT_EQ(error::AttestationSGX_DebugEnabled, Check(p));
}

// The debug bit is OE_REPORT_ATTRIBUTES_DEBUG (0x1), which is not the raw
// SGX_FLAGS_DEBUG (0x2); 0x2 is OE_REPORT_ATTRIBUTES_REMOTE.
TEST_F(AttestPolicyTest, DebugBitMatchesOEClaimEncoding) {
  ASSERT_EQ(0x1u, kAttributeDebug);
  auto p = Identity();
  p.attributes = 0x2;
  ASSERT_EQ(error::OK, Check(p));
  p.attributes = 0x1;
  ASSERT_EQ(error::AttestationSGX_DebugEnabled, Check(p));
}

TEST_F(AttestPolicyTest, RejectsWrongLengthClaims) {
  auto p = Identity();
  p.mrenclave = std::string(16, '\xaa');
  ASSERT_EQ(error::Env_WrongMRENCLAVE, Check(p));
  p = Identity();
  p.signer_id = std::string(16, '\xbb');
  ASSERT_EQ(error::AttestationSGX_WrongSignerId, Check(p));
  p = Identity();
  p.product_id = std::string(8, '\xcc');
  ASSERT_EQ(error::AttestationSGX_WrongProductId, Check(p));
}

TEST_F(AttestPolicyTest, FailsClosedOnUnsetExpectedValues) {
  auto expected = Identity();
  expected.mrenclave.clear();
  ASSERT_EQ(error::Env_MissingMRENCLAVE,
            CheckPeerIdentity(Identity(), expected));

  expected = Identity();
  expected.signer_id.clear();
  ASSERT_EQ(error::AttestationSGX_MissingSignerId,
            CheckPeerIdentity(Identity(), expected));

  expected = Identity();
  expected.product_id.clear();
  ASSERT_EQ(error::AttestationSGX_MissingProductId,
            CheckPeerIdentity(Identity(), expected));

  ASSERT_EQ(error::Env_MissingMRENCLAVE,
            CheckPeerIdentity(PeerIdentity(), PeerIdentity()));
}

}  // namespace svr2::attestation::sgx
