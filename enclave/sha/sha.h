// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SHA_SHA_H__
#define __SVR2_SHA_SHA_H__

#include <stddef.h>
#include <stdint.h>
#include <array>

namespace svr2::sha {

typedef std::array<uint8_t, 32> Sha256Sum;
typedef std::array<uint8_t, 64> Sha512Sum;

Sha256Sum Sha256(
    const uint8_t* d1, size_t s1,
    const uint8_t* d2, size_t s2,
    const uint8_t* d3, size_t s3);
Sha512Sum Sha512(
    const uint8_t* d1, size_t s1,
    const uint8_t* d2, size_t s2,
    const uint8_t* d3, size_t s3);

template <class T1>
Sha256Sum Sha256(const T1& t1) {
  return Sha256(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      nullptr, 0,
      nullptr, 0);
}
template <class T1, class T2>
Sha256Sum Sha256(const T1& t1, const T2& t2) {
  return Sha256(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      reinterpret_cast<const uint8_t*>(t2.data()), t2.size(),
      nullptr, 0);
}
template <class T1, class T2, class T3>
Sha256Sum Sha256(const T1& t1, const T2& t2, const T3& t3) {
  return Sha256(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      reinterpret_cast<const uint8_t*>(t2.data()), t2.size(),
      reinterpret_cast<const uint8_t*>(t3.data()), t3.size());
}

template <class T1>
Sha512Sum Sha512(const T1& t1) {
  return Sha512(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      nullptr, 0,
      nullptr, 0);
}
template <class T1, class T2>
Sha512Sum Sha512(const T1& t1, const T2& t2) {
  return Sha512(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      reinterpret_cast<const uint8_t*>(t2.data()), t2.size(),
      nullptr, 0);
}
template <class T1, class T2, class T3>
Sha512Sum Sha512(const T1& t1, const T2& t2, const T3& t3) {
  return Sha512(
      reinterpret_cast<const uint8_t*>(t1.data()), t1.size(),
      reinterpret_cast<const uint8_t*>(t2.data()), t2.size(),
      reinterpret_cast<const uint8_t*>(t3.data()), t3.size());
}

}  // namespace svr2::sha

#endif  // __SVR2_SHA_SHA_H__
