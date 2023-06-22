// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// WARNING:  This header includes non-namespaced outputs.

#ifndef __SVR2_SEVTYPES_SEVTYPES_H__
#define __SVR2_SEVTYPES_SEVTYPES_H__

#include <sys/ioctl.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef unsigned long long __u64;
#define __packed __attribute__((__packed__))
#include "sevtypes/sev-guest.h"    // From Linux kernel headers (linux-hwe-5.19-headers-5.19.0-43)  LICENSE=GPL2
#define SEV_FW_BLOB_MAX_SIZE (16 << 10)  // Max blob size (16kb)

#endif  // __SVR2_SEVTYPES_SEVTYPES_H__
