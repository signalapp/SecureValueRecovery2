// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/base64.h"
#include <stdint.h>
#include "util/macros.h"
#include "metrics/metrics.h"

namespace svr2::util {
namespace {
const Base64Encoding B64STD_{
  .decode = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  },
  .encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
};

const Base64Encoding B64URL_{
  .decode = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  },
  .encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};
}  // namespace
const Base64Encoding* const B64STD = &B64STD_;
const Base64Encoding* const B64URL = &B64URL_;

static const char padding = '=';

error::Error B64DecodeInline(std::string* inout, const Base64Encoding* const encoding) {
  size_t j = 0;
  uint16_t accumulator = 0;
  uint16_t bits = 0;
  for (size_t i = 0; i < inout->size(); i++) {
    char next = inout->at(i);
    if (next == padding) {
      // We're very permissive with padding.  We allow no padding,
      // or any number of padding characters at the end of a string.
      for (i++; i < inout->size(); i++) {
        if (inout->at(i) != padding) {
          return COUNTED_ERROR(Util_Base64InvalidPadding);
        }
      }
      break;
    }
    char c = encoding->decode[(size_t) next];
    if (c == -1) {
      LOG(DEBUG) << "Invalid character: " << ((int) next);
      return COUNTED_ERROR(Util_Base64InvalidChar);
    }
    accumulator = (accumulator << 6) | c;
    bits += 6;
    if (bits >= 8) {
      CHECK(j <= i);
      (*inout)[j++] = accumulator >> (bits - 8);
      bits -= 8;
    }
  }
  inout->resize(j);
  return error::OK;
}

std::string Base64Encode(const uint8_t* in, size_t in_size, const Base64Encoding* const encoding, bool padding) {
  std::string out;
  size_t bits = 0;
  uint16_t work = 0;
  const uint8_t* end = in + in_size;
  while (in < end) {
    bits += 8;
    work = (work << 8) | *in;
    in++;
    while (bits >= 6) {
      bits -= 6;
      uint8_t offset = (work >> bits) & 0x3f;
      out.append(1, encoding->encode[offset]);
    }
  }
  if (bits) {
    work <<= 6 - bits;
    uint8_t offset = work & 0x3f;
    out.append(1, encoding->encode[offset]);
    if (padding) {
      out.append(bits == 2 ? "==" : "=");
    }
  }
  return out;
}

std::string Base64Encode(const char* c, const Base64Encoding* const encoding, bool padding) {
  return Base64Encode(reinterpret_cast<const uint8_t*>(c), strlen(c), encoding, padding);
}

}  // namespace svr2::util
