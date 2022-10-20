// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_TICKS_H__
#define __SVR2_UTIL_TICKS_H__

#include <stdint.h>
#include <time.h>

namespace svr2::util {

typedef int64_t Ticks;
extern const Ticks InvalidTicks;
typedef time_t UnixSecs;

}  // namespace svr2::util

#endif // __SVR2_UTIL_TICKS_H__
