// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SIP_HASHER_H__
#define __SVR2_SIP_HASHER_H__

#include <cstddef>
#include <stdint.h>
#include <array>

namespace svr2::sip {

class Half {
 public:
  Half();
  Half(const Half& copy);
  Half(const std::array<uint8_t, 8>& key);
  uint64_t HashU64(const void* data, size_t bytes) const;
  std::array<uint8_t, 8> Hash8(const void* data, size_t bytes) const;
  void ResetKey(const std::array<uint8_t, 8>& key);
 private:
  uint8_t halfsiphash_key_[8];
};

class Full {
 public:
  Full();
  Full(const Full& copy);
  Full(const std::array<uint8_t, 16>& key);
  uint64_t HashU64(const void* data, size_t bytes) const;
  std::array<uint8_t, 8> Hash8(const void* data, size_t bytes) const;
  std::array<uint8_t, 16> Hash16(const void* data, size_t bytes) const;
  void ResetKey(const std::array<uint8_t, 16>& key);
 private:
  uint8_t siphash_key_[16];
};

extern Half HalfZero;
extern Full FullZero;

}  // namespace svr2::sip

#endif  // __SVR2_SIP_HASHER_H__
