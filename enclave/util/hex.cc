// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/hex.h"
#include "metrics/metrics.h"

namespace svr2::util {
namespace {

inline uint8_t HexCharToNibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return 0xa + (c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    return 0xa + (c - 'A');
  } else {
    return 0xFF;
  }
}

}  // namespace

std::string BytesToHex(const uint8_t* in, size_t size) {
  static const char* nibbles = "0123456789abcdef";
  std::string out(size * 2, ' ');
  for (size_t i = 0; i < size; i++) {
    out[i*2+0] = nibbles[(in[i] & 0xf0) >> 4];
    out[i*2+1] = nibbles[(in[i] & 0x0f) >> 0];
  }
  return out;
}

std::pair<std::string, error::Error> HexToBytes(const char* in, size_t in_size) {
  std::string out;
  if (in_size % 2 != 0) {
    return std::make_pair(std::move(out), COUNTED_ERROR(Util_HexBytesSize));
  }
  for (size_t i = 0; i < in_size; i += 2) {
    uint8_t n1 = HexCharToNibble(in[i]);
    uint8_t n2 = HexCharToNibble(in[i+1]);
    if (n1 == 0xFF || n2 == 0xFF) {
      return std::make_pair(std::move(out), COUNTED_ERROR(Util_HexCharInvalid));
    }
    out.append(1, static_cast<char>((n1 << 4) | n2));
  }
  return std::make_pair(std::move(out), error::OK);
}

}  // namespace svr2::util
