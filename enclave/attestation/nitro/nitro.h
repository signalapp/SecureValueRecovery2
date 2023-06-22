// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_NITRO_NITRO_H__
#define __SVR2_ATTESTATION_NITRO_NITRO_H__

#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/base.h>
#include <openssl/ecdsa.h>
#include "proto/error.pb.h"
#include "util/ticks.h"

namespace svr2::attestation::nitro {

typedef std::string TextString;
typedef std::vector<uint8_t> ByteString;

struct CoseSign1 {
  ByteString protected_header;
  // nitro has no unprotected header
  ByteString payload;
  ByteString signature;

  void Clear();
  bool Valid() const;
  error::Error ParseFromBytes(const uint8_t* in, size_t size);
  std::pair<ByteString, error::Error> SigningBytes() const;
};

struct AttestationDoc {
  std::string module_id;
  std::string digest;
  int64_t timestamp;
  std::map<int, std::vector<uint8_t>> pcrs;
  std::vector<uint8_t> certificate;
  std::vector<std::vector<uint8_t>> cabundle;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> user_data;
  std::vector<uint8_t> nonce;

  void Clear();
  std::pair<bssl::UniquePtr<X509>, error::Error> Certificate() const;
  std::pair<bssl::UniquePtr<STACK_OF(X509)>, error::Error> CABundle() const;

  // Valid returns true if this AttestationDoc passes simple checks for validity.
  // It does not perform heavier-handed checks like parsing certificates; that's
  // done as part of verification.
  bool Valid() const;
  error::Error ParseFromBytes(const uint8_t* in, size_t size);
};

error::Error Verify(const AttestationDoc& doc, const CoseSign1& from, util::UnixSecs now);

}  // namespace svr2::attestation::nitro

#endif  // __SVR2_ATTESTATION_NITRO_NITRO_H__
