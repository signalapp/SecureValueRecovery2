// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "hmac/hmac.h"
#include <sodium/crypto_auth_hmacsha256.h>
#include <string.h>

namespace svr2::hmac {

sha::Sha256Sum HmacSha256(const HmacSha256Key& key, const uint8_t* data_start, size_t data_size) {
  sha::Sha256Sum out;
  crypto_auth_hmacsha256(out.data(), data_start, data_size, key.data());
  return out;
}

}  // namespace svr2::hmac
