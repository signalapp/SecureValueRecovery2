// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "sip/hasher.h"
#include "env/env.h"
#include "util/endian.h"
extern "C" {
#include "sip/halfsiphash.h"
#include "sip/siphash.h"
}  // extern "C"

namespace svr2::sip {

static const std::array<uint8_t, 8> half_zeros = {0};
Half HalfZero(half_zeros);
static const std::array<uint8_t, 16> full_zeros = {0};
Full FullZero(full_zeros);

Half::Half() {
  CHECK(error::OK == env::environment->RandomBytes(halfsiphash_key_, sizeof(halfsiphash_key_)));
}
Half::Half(const Half& copy) {
  memcpy(halfsiphash_key_, copy.halfsiphash_key_, sizeof(halfsiphash_key_));
}
Half::Half(const std::array<uint8_t, 8>& key) {
  ResetKey(key);
}
std::array<uint8_t, 8> Half::Hash8(const void* data, size_t size) const {
  std::array<uint8_t, 8> out;
  halfsiphash(data, size, halfsiphash_key_, out.data(), out.size());
  return out;
}
void Half::ResetKey(const std::array<uint8_t, 8>& key) {
  CHECK(sizeof(halfsiphash_key_) == key.size());
  memcpy(halfsiphash_key_, key.data(), sizeof(halfsiphash_key_));
}
uint64_t Half::HashU64(const void* data, size_t size) const {
  auto bytes = Hash8(data, size);
  return util::BigEndian64FromBytes(bytes.data());
}

Full::Full() {
  CHECK(error::OK == env::environment->RandomBytes(siphash_key_, sizeof(siphash_key_)));
}
Full::Full(const Full& copy) {
  memcpy(siphash_key_, copy.siphash_key_, sizeof(siphash_key_));
}
Full::Full(const std::array<uint8_t, 16>& key) {
  ResetKey(key);
}
std::array<uint8_t, 8> Full::Hash8(const void* data, size_t size) const {
  std::array<uint8_t, 8> out;
  siphash(data, size, siphash_key_, out.data(), out.size());
  return out;
}
uint64_t Full::HashU64(const void* data, size_t size) const {
  auto bytes = Hash8(data, size);
  return util::BigEndian64FromBytes(bytes.data());
}
std::array<uint8_t, 16> Full::Hash16(const void* data, size_t size) const {
  std::array<uint8_t, 16> out;
  siphash(data, size, siphash_key_, out.data(), out.size());
  return out;
}
void Full::ResetKey(const std::array<uint8_t, 16>& key) {
  CHECK(sizeof(siphash_key_) == key.size());
  memcpy(siphash_key_, key.data(), sizeof(siphash_key_));
}

}  // namespace svr2::sip
