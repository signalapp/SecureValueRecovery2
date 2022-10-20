// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "hmac/hmac.h"
#include <sodium/crypto_auth_hmacsha256.h>
#include <string.h>

namespace svr2::hmac {

std::array<uint8_t, 32> Sha256(const std::string& input) {
  crypto_hash_sha256_state sha;
  crypto_hash_sha256_init(&sha);
  crypto_hash_sha256_update(&sha, reinterpret_cast<const unsigned char*>(input.data()), input.size());
  std::array<uint8_t, 32> out;
  crypto_hash_sha256_final(&sha, out.data());
  return out;
}

std::array<uint8_t, 32> HmacSha256(const std::array<uint8_t, 32>& key, const std::string& input) {
  std::array<uint8_t, 32> out;
  crypto_auth_hmacsha256(out.data(), reinterpret_cast<const unsigned char*>(input.data()), input.size(), key.data());
  return out;
}

}  // namespace svr2::hmac
