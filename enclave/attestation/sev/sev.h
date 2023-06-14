// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ATTESTATION_SEV_SEV_H__
#define __SVR2_ATTESTATION_SEV_SEV_H__

#include "proto/error.pb.h"

namespace svr2::attestation::sev {

error::Error ResizeCertificates(const uint8_t* certs, uint32_t* certs_size);

}  // namespace svr2::attestation::sev

#endif  // __SVR2_ATTESTATION_SEV_SEV_H__
