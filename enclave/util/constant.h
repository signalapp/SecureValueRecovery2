// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_CONSTANT_H__
#define __SVR2_UTIL_CONSTANT_H__

namespace svr2::util {

static inline bool ConstantTimeEqualsBytes(const uint8_t* a, const uint8_t* b, size_t size) {
  uint8_t out = 0;
  while (size--) {
    out |= (*a++) ^ (*b++);
  }
  return out == 0;
}

// Templatized to work on std::array and std::string.
template <class T1, class T2>
static bool ConstantTimeEqualsPrefix(const T1& a, const T2& b, size_t prefix_size) {
  if (a.size() < prefix_size || b.size() < prefix_size) return false;  // not constant time, but we generally don't care.
  return ConstantTimeEqualsBytes(
      reinterpret_cast<const uint8_t*>(a.data()),
      reinterpret_cast<const uint8_t*>(b.data()),
      prefix_size);
}

// Templatized to work on std::array and std::string.
template <class T1, class T2>
static bool ConstantTimeEquals(const T1& a, const T2& b) {
  if (a.size() != b.size()) return false;  // not constant time, but we generally don't care.
  return ConstantTimeEqualsPrefix(a, b, a.size());
}

}  // namespace svr2::util

#endif  // __SVR2_UTIL_CONSTANT_H__
