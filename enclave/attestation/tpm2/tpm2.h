// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_TPM2_TPM2__
#define __SVR2_ATTESTATION_TPM2_TPM2__

#include <string>
#include <array>
#include <utility>
#include <vector>
#include <ostream>
#include <stdint.h>
#include "proto/error.pb.h"
#include "util/macros.h"
#include <openssl/x509.h>

namespace svr2::attestation::tpm2 {

#define TPM2_AZURE_MIN_FIRMWARE_VERSION 0x2020031200120003ULL

template <std::size_t N>
std::array<uint8_t, N> to_byte_array(const uint8_t* p) {
  std::array<uint8_t, N> out;
  std::copy(p, p+N, out.begin());
  return out;
}

struct Clock {
  uint64_t millis_since_clear;
  uint32_t resets;
  uint32_t restarts;
  bool safe;
};

typedef std::array<std::array<uint8_t, 32>, 24> PCRs;

error::Error PCRsFromString(const std::string& data, PCRs* out);

class Report {
 public:
  static std::pair<Report, error::Error> FromString(const std::string& data);

  std::array<uint8_t, 32> key_hash() const {
    return to_byte_array<32>(start() + key_offset_);
  }
  std::array<uint8_t, 32> pcr_digest() const {
    return to_byte_array<32>(start() + pcr_digest_offset_);
  }
  std::array<uint8_t, 32> nonce() const {
    return to_byte_array<32>(start() + nonce_offset_);
  }
  uint64_t firmware_version() const { return firmware_version_; }
  const Clock& clock() const { return clock_; }
  const std::string& data() const { return data_; }
  error::Error VerifyPCRs(const PCRs& pcrs) const;

 private:
  Report(const std::string& data) : data_(data) {}
  bool Parse();
  const uint8_t* start() const {
    return reinterpret_cast<const uint8_t*>(data_.data());
  }
  friend std::ostream& operator<<(std::ostream& os, const Report& report);

  std::string data_;
  size_t key_offset_;
  size_t nonce_offset_;
  Clock clock_;
  uint64_t firmware_version_;
  size_t pcr_digest_offset_;
};

class Signature {
 public:
  static std::pair<Signature, error::Error> FromString(const std::string& data);
  const std::array<uint8_t, 256>& sig() const { return sig_; }
  error::Error VerifyReport(const Report& report, X509* cert) const;

 private:
  Signature() {}
  bool Parse(const std::string& data);
  std::array<uint8_t, 256> sig_;
};

std::ostream& operator<<(std::ostream& os, const PCRs& pcrs);
std::ostream& operator<<(std::ostream& os, const Report& report);

}  // namespace svr2::attestation::tpm2

#endif  // __SVR2_ATTESTATION_TPM2_TPM2__
