// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_SEV_LINUX_TYPES_H__
#define __SVR2_ENV_SEV_LINUX_TYPES_H__

#include <sys/ioctl.h>
#include <stdint.h>

namespace svr2::env::sev {

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define __packed __attribute__((__packed__))
#include "env/sev/sev-guest.h"    // From Linux kernel headers (linux-hwe-5.19-headers-5.19.0-43)  LICENSE=GPL2
#include "env/sev/attestation.h"  // From https://github.com/AMDESE/sev-guest/blob/62317d7de4d79d4ca887b357dddf072082b0b078/include/attestation.h  LICENSE=Apache
#define SEV_FW_BLOB_MAX_SIZE (16 << 10)  // Max blob size (16kb)

}  // namespace svr2::env::sev

#endif  // __SVR2_ENV_SEV_LINUX_TYPES_H__
