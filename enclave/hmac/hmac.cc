// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "hmac/hmac.h"
#include <sodium/crypto_auth_hmacsha256.h>
#include <string.h>

namespace svr2::hmac {

Sha256Sum Sha256(const uint8_t* data_start, size_t data_size) {
  crypto_hash_sha256_state sha;
  crypto_hash_sha256_init(&sha);
  crypto_hash_sha256_update(&sha, data_start, data_size);
  Sha256Sum out;
  crypto_hash_sha256_final(&sha, out.data());
  return out;
}

Sha256Sum HmacSha256(const HmacSha256Key& key, const uint8_t* data_start, size_t data_size) {
  Sha256Sum out;
  crypto_auth_hmacsha256(out.data(), data_start, data_size, key.data());
  return out;
}

}  // namespace svr2::hmac
