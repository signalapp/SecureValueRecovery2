// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "sha/sha.h"
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha512.h>

namespace svr2::sha {

Sha256Sum Sha256(
    const uint8_t* d1, size_t s1,
    const uint8_t* d2, size_t s2,
    const uint8_t* d3, size_t s3) {
  Sha256Sum h;
  crypto_hash_sha256_state s;
  crypto_hash_sha256_init(&s);
  crypto_hash_sha256_update(&s, d1, s1);
  crypto_hash_sha256_update(&s, d2, s2);
  crypto_hash_sha256_update(&s, d3, s3);
  crypto_hash_sha256_final(&s, h.data());
  return h;
}

Sha512Sum Sha512(
    const uint8_t* d1, size_t s1,
    const uint8_t* d2, size_t s2,
    const uint8_t* d3, size_t s3) {
  Sha512Sum h;
  crypto_hash_sha512_state s;
  crypto_hash_sha512_init(&s);
  crypto_hash_sha512_update(&s, d1, s1);
  crypto_hash_sha512_update(&s, d2, s2);
  crypto_hash_sha512_update(&s, d3, s3);
  crypto_hash_sha512_final(&s, h.data());
  return h;
}

}  // namespace svr2::sha
