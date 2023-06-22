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
std::pair<std::array<uint8_t, N>, error::Error> StringToByteArray(const std::string& str) {
  std::array<uint8_t, N> result{0};
  if (str.size() > N) {
    return std::make_pair(result, error::Util_ArrayCopyTooBig);
  }
  std::copy(str.begin(), str.end(), result.begin());
  return std::make_pair(result, error::OK);
}

std::string ByteVectorToString(const std::vector<uint8_t>& bytes);
inline std::string ByteVectorToString(const std::vector<uint8_t>& bytes) {
  std::string result;
  result.resize(bytes.size());
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

}  // namespace svr2::util

#endif // __SVR2_UTIL_BYTES_H
