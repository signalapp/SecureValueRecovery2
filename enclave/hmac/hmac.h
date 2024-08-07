// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_HMAC_HMAC_H__
#define __SVR2_HMAC_HMAC_H__

#include <array>
#include <string>
#include <string.h>
#include "sha/sha.h"

namespace svr2::hmac {

typedef std::array<uint8_t, 32> HmacSha256Key;

sha::Sha256Sum HmacSha256(const HmacSha256Key& key, const uint8_t* data_start, size_t data_size);

inline sha::Sha256Sum HmacSha256(const HmacSha256Key& key, const char* c_str) {
  return HmacSha256(key, reinterpret_cast<const uint8_t*>(c_str), strlen(c_str));
}
template <class T>
sha::Sha256Sum HmacSha256(const HmacSha256Key& key, const T& data) {
  return HmacSha256(key, reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

}  // namespace svr2::hmac

#endif  // __SVR2_HMAC_HMAC_H__
