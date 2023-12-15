// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "attestation/tpm2/tpm2.h"
#include "util/endian.h"
#include "util/log.h"
#include "util/hex.h"
#include "util/constant.h"
#include "metrics/metrics.h"

namespace svr2::attestation::tpm2 {

namespace {
const uint32_t TPM_GENERATED_VALUE = 0xff544347UL;
const uint16_t TPM_ST_ATTEST_QUOTE = 0x8018;
const uint16_t SHA256_ALG = 0x000b;
const size_t NONCE_SIZE = 32;
const size_t SHA256_SIZE = 32;
const uint32_t ALL_24_PCRs = 0x03ffffffUL;  // Each PCR is a single bit.  This value is the lower 24 bits set.
}  // namespace

std::pair<Report, error::Error> Report::FromString(const std::string& data) {
  Report r(data);
  auto err = r.Parse() ? error::OK : error::AttestationTPM2_ParseReport;
  return std::make_pair(std::move(r), err);
}

bool Report::Parse() {
  const uint8_t* d = start();
  const uint8_t* e = d + data_.size();
  if (d + 4 > e ||
      util::BigEndian32FromBytes(d) != TPM_GENERATED_VALUE) {
    LOG(ERROR) << "report must start with TPM_GENERATED_VALUE";
    return false;
  }
  d += 4;
  if (d + 2 > e ||
      util::BigEndian16FromBytes(d) != TPM_ST_ATTEST_QUOTE) {
    LOG(ERROR) << "report type must be TPM_ST_ATTEST_QUOTE";
    return false;
  }
  d += 2;
  if (d + SHA256_SIZE + 2 + 2 > e ||
      util::BigEndian16FromBytes(d+0) != 2 + SHA256_SIZE || // 34 bytes
      util::BigEndian16FromBytes(d+2) != SHA256_ALG) { // sha256
    LOG(ERROR) << "key should be presented as sha256, 34 bytes (alg+val)";
    return false;
  }
  d += 2 + 2;
  key_offset_ = d - start();
  d += SHA256_SIZE;
  if (d + 2 > e ||
      util::BigEndian16FromBytes(d) != NONCE_SIZE) {
    LOG(ERROR) << "nonce size";
    return false;
  }
  d += 2;
  if (d + NONCE_SIZE > e) {
    LOG(ERROR) << "nonce space";
    return false;
  }
  nonce_offset_ = d - start();
  d += NONCE_SIZE;
  if (d + 17 > e) {
    LOG(ERROR) << "clock space";
    return false;
  }
  clock_.millis_since_clear = util::BigEndian64FromBytes(d);
  d += 8;
  clock_.resets = util::BigEndian32FromBytes(d);
  d += 4;
  clock_.restarts = util::BigEndian32FromBytes(d);
  d += 4;
  clock_.safe = (*d) == 0x01;
  d += 1;
  if (d + 8 > e) {
    LOG(ERROR) << "firmware space";
    return false;
  }
  firmware_version_ = util::BigEndian64FromBytes(d);
  d += 8;
  if (d + 4 > e ||
      util::BigEndian32FromBytes(d) != 1) {  // Total number of PCR selection sets
    LOG(ERROR) << "only allow a single PCR selection set";
    return false;
  }
  d += 4;
  if (d + 2 > e ||
      util::BigEndian16FromBytes(d) != SHA256_ALG) {
    LOG(ERROR) << "must use sha256 PCRs";
    return false;
  }
  d += 2;
  if (d + 4 > e ||
      util::BigEndian32FromBytes(d) != ALL_24_PCRs) {
    LOG(ERROR) << "must use all 24 PCRs";
    return false;
  }
  d += 4;
  if (d + 2 > e ||
      util::BigEndian16FromBytes(d) != SHA256_SIZE) {
    LOG(ERROR) << "must have 32 byte pcr_digest (it's sha256)";
    return false;
  }
  d += 2;
  if (d + SHA256_SIZE > e) {
    LOG(ERROR) << "pcr_digest cut off early";
    return false;
  }
  pcr_digest_offset_ = d - start();
  d += SHA256_SIZE;
  if (d != e) {
    LOG(ERROR) << "Trailing bytes";
    return false;
  }
  return true;
}

error::Error Report::VerifyPCRs(const PCRs& pcrs) const {
  std::array<uint8_t, 32> digest;
  SHA256_CTX ctx;
  if (1 != SHA256_Init(&ctx)) return COUNTED_ERROR(AttestationTPM2_PCRDigest);
  for (size_t i = 0; i < pcrs.size(); i++) {
    if (1 != SHA256_Update(&ctx, pcrs[i].data(), pcrs[i].size())) return COUNTED_ERROR(AttestationTPM2_PCRDigest);
  }
  if (1 != SHA256_Final(digest.data(), &ctx)) return COUNTED_ERROR(AttestationTPM2_PCRDigest);
  if (!util::ConstantTimeEqualsBytes(digest.data(), start() + pcr_digest_offset_, digest.size())) {
    return COUNTED_ERROR(AttestationTPM2_PCRVerify);
  }
  return error::OK;
}

error::Error PCRsFromString(const std::string& data, PCRs* out) {
  if (data.size() != 24 * 32) {
    return error::AttestationTPM2_ParsePCRs;
  }
  const uint8_t* d = reinterpret_cast<const uint8_t*>(data.data());
  for (size_t i = 0; i < 24; i++) {
    (*out)[i] = to_byte_array<32>(d);
    d += 32;
  }
  return error::OK;
}

std::ostream& operator<<(std::ostream& os, const PCRs& pcrs) {
  os << "TPM2_PCRS{";
  for (size_t i = 0; i < 24; i++) {
    os << " pcr" << i << ":" << util::ToHex(pcrs[i]);
  }
  os << " }";
  return os;
}

std::ostream& operator<<(std::ostream& os, const Report& report) {
  os << "TPM2_REPORT{"
       << " key_hash:" << util::ToHex(report.key_hash())
       << " nonce:" << util::ToHex(report.nonce())
       << " pcr_digest:" << util::ToHex(report.pcr_digest())
       << " clock{"
         << " millis_since_clear:" << report.clock_.millis_since_clear
         << " resets:" << report.clock_.resets
         << " restarts:" << report.clock_.restarts
         << " safe:" << report.clock_.safe
       << " }"
       << " firmware_version:" << report.firmware_version_
     << " }";
  return os;
}

std::pair<Signature, error::Error> Signature::FromString(const std::string& data) {
  Signature s;
  auto err = s.Parse(data) ? error::OK : error::AttestationTPM2_ParseSignature;
  return std::make_pair(std::move(s), err);
}

bool Signature::Parse(const std::string& data) {
  if (data.size() != 262) {
    LOG(ERROR) << "signature should be a 6-byte prefix and a 256-byte value";
    return false;
  }
  const uint8_t* d = reinterpret_cast<const uint8_t*>(data.data());
  if (util::BigEndian16FromBytes(d+0) != 0x0014) {
    LOG(ERROR) << "alg should be TPM_ALG_RSASSA";
    return false;
  } else if (util::BigEndian16FromBytes(d+2) != 0x000b) {
    LOG(ERROR) << "hash should be sha256";
    return false;
  } else if (util::BigEndian16FromBytes(d+4) != 0x0100) {
    LOG(ERROR) << "sig value size should be 256";
    return false;
  }
  sig_ = to_byte_array<256>(d+6);
  return true;
}

error::Error Signature::VerifyReport(const Report& report, X509* cert) const {
  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert));
  if (!pkey) return COUNTED_ERROR(AttestationTPM2_CryptoAllocate);
  RSA* rsa_key_not_owned = EVP_PKEY_get0_RSA(pkey.get());
  if (rsa_key_not_owned == nullptr) return COUNTED_ERROR(AttestationTPM2_CertificateNotRSA);
  std::array<uint8_t, 32> digest;
  SHA256_CTX sha256_ctx;
  if (1 != SHA256_Init(&sha256_ctx) ||
      1 != SHA256_Update(&sha256_ctx, report.data().data(), report.data().size()) ||
      1 != SHA256_Final(digest.data(), &sha256_ctx)) {
    return COUNTED_ERROR(AttestationTPM2_SignatureDigest);
  }
  if (1 != RSA_verify(
      NID_sha256,
      digest.data(), digest.size(), 
      sig_.data(), sig_.size(),
      rsa_key_not_owned)) {
    return COUNTED_ERROR(AttestationTPM2_SignatureVerify);
  }
  return error::OK;
}

}  // namespace svr2::attestation::tpm2
