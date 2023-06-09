// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_HEX_H__
#define __SVR2_UTIL_HEX_H__

#include <string>
#include <algorithm>
#include "proto/error.pb.h"

namespace svr2::util {

std::string BytesToHex(const uint8_t* in, size_t size);

// Turns the `s`-byte prefix of `in` into `s*2` hex characters and returns it as a string.
template <class T>
std::string PrefixToHex(const T& in, size_t s) {
  return BytesToHex(reinterpret_cast<const uint8_t*>(in.data()), std::min(s, in.size()));
}

// Turns the bytes of `in` into `in.size()*2` hex characters and returns it as a string.
template <class T>
std::string ToHex(const T& in) {
  return PrefixToHex(in, in.size());
}

template <class T>
std::string ValueToHex(const T& in) {
  return BytesToHex(reinterpret_cast<const uint8_t*>(&in), sizeof(in));
}

std::pair<std::string, error::Error> HexToBytes(const char* in, size_t in_size);
inline std::pair<std::string, error::Error> HexToBytes(const std::string& in) {
  return HexToBytes(in.data(), in.size());
}

}  // namespace svr2::util

#endif  // __SVR2_UTIL_HEX_H__
