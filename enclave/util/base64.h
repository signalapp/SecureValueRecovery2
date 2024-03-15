// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_BASE64_BASE64_H__
#define __SVR2_ATTESTATION_BASE64_BASE64_H__

#include <string>
#include "proto/error.pb.h"

namespace svr2::util {

struct Base64Encoding {
  const char decode[256];
  const char* encode;
};

extern const Base64Encoding* const B64URL;
extern const Base64Encoding* const B64STD;

// B64DecodeInline takes in a string containing base64 and modifies
// it to contain the base64-decoded data.  `*inout` will be modified,
// and should an error be returned, it will most likely not contain
// the same data as it had when this function was initially called.
error::Error B64DecodeInline(std::string* inout, const Base64Encoding* const encoding);
std::string Base64Encode(const uint8_t* in, size_t in_size, const Base64Encoding* const encoding, bool padding);
template <class T>
std::string Base64Encode(const T& t, const Base64Encoding* const encoding, bool padding) {
  return Base64Encode(reinterpret_cast<const uint8_t*>(t.data()), t.size(), encoding, padding);
}
std::string Base64Encode(const char* c, const Base64Encoding* const encoding, bool padding);
}  // namespace svr2::util

#endif  // __SVR2_ATTESTATION_BASE64_BASE64_H__
