// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SIP_HASHER_H__
#define __SVR2_SIP_HASHER_H__

#include <cstddef>
#include <stdint.h>

namespace svr2::sip {

class Hasher {
 public:
  Hasher();
  Hasher(const Hasher& copy);
 protected:
  size_t Hash(const void* data, size_t bytes) const;
 private:
  uint8_t halfsiphash_key_[8];
};

}  // namespace svr2::sip

#endif  // __SVR2_SIP_HASHER_H__
