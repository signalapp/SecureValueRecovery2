// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_HMAC_HMAC_H__
#define __SVR2_HMAC_HMAC_H__

#include <array>
#include <string>

namespace svr2::hmac {

std::array<uint8_t, 32> Sha256(const std::string& input);
std::array<uint8_t, 32> HmacSha256(const std::array<uint8_t, 32>& key, const std::string& input);

}  // namespace svr2::hmac

#endif  // __SVR2_HMAC_HMAC_H__
