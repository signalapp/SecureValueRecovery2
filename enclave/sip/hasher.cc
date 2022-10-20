// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "sip/hasher.h"
#include "env/env.h"
#include "util/endian.h"
extern "C" {
#include "sip/halfsiphash.h"
}  // extern "C"

namespace svr2::sip {

Hasher::Hasher() {
  CHECK(error::OK == env::environment->RandomBytes(halfsiphash_key_, sizeof(halfsiphash_key_)));
}
Hasher::Hasher(const Hasher& copy) {
  memcpy(halfsiphash_key_, copy.halfsiphash_key_, sizeof(halfsiphash_key_));
}
size_t Hasher::Hash(const void* data, size_t size) const {
  uint8_t out[8];
  halfsiphash(data, size, halfsiphash_key_, out, sizeof(out));
  return util::BigEndian64FromBytes(out);
}

}  // namespace svr2::sip
