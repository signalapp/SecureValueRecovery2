// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_BASE64_BASE64_H__
#define __SVR2_ATTESTATION_BASE64_BASE64_H__

#include <string>
#include "proto/error.pb.h"

namespace svr2::util {

extern const char B64URL[256];
extern const char B64STD[256];

// B64DecodeInline takes in a string containing base64 and modifies
// it to contain the base64-decoded data.  `*inout` will be modified,
// and should an error be returned, it will most likely not contain
// the same data as it had when this function was initially called.
error::Error B64DecodeInline(std::string* inout, const char type[256]);

}  // namespace svr2::util

#endif  // __SVR2_ATTESTATION_BASE64_BASE64_H__
