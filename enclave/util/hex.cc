// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/hex.h"

namespace svr2::util {

std::string BytesToHex(const uint8_t* in, size_t size) {
  static const char* nibbles = "0123456789abcdef";
  std::string out(size * 2, ' ');
  for (size_t i = 0; i < size; i++) {
    out[i*2+0] = nibbles[(in[i] & 0xf0) >> 4];
    out[i*2+1] = nibbles[(in[i] & 0x0f) >> 0];
  }
  return out;
}

std::string HexToBytes(std::string hex) {
  std::string bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char) strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

}  // namespace svr2::util
