// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_HEX_H__
#define __SVR2_UTIL_HEX_H__

#include <string>
#include <algorithm>

namespace svr2::util {

std::string BytesToHex(const uint8_t* in, size_t size);
std::string HexToBytes(std::string hex);

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

}  // namespace svr2::util

#endif  // __SVR2_UTIL_HEX_H__
