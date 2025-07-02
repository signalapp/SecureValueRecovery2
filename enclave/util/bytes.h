// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_BYTES_H
#define __SVR2_UTIL_BYTES_H

#include <cstddef>
#include <utility>
#include <string>
#include <array>
#include "util/macros.h"
#include "proto/error.pb.h"

namespace svr2::util {

template<size_t N>
std::string ByteArrayToString(const std::array<uint8_t, N>& bytes) {
  std::string result;
  result.resize(N, '\0');
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

template<size_t N>
error::Error StringIntoByteArray(const std::string& str, std::array<uint8_t, N>* result) {
  if (str.size() > N) {
    return error::Util_ArrayCopyTooBig;
  }
  std::copy(str.begin(), str.end(), result->begin());
  return error::OK;
}

template<size_t N>
std::pair<std::array<uint8_t, N>, error::Error> StringToByteArray(const std::string& str) {
  std::array<uint8_t, N> result{0};
  error::Error err = StringIntoByteArray(str, &result);
  return std::make_pair(result, err);
}

std::string ByteVectorToString(const std::vector<uint8_t>& bytes);
inline std::string ByteVectorToString(const std::vector<uint8_t>& bytes) {
  std::string result;
  result.resize(bytes.size());
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

// Attempt to clear a section of memory to zeros in a way that should
// be difficult for compilers to ignore.
// We avoid inlining so the compiler can't then decide to remove certain
// parts of this function at the call site.
void MemZeroS(void* v, size_t s) __attribute__((noinline));

}  // namespace svr2::util

#endif // __SVR2_UTIL_BYTES_H
