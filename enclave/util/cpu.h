// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_CPU_H__
#define __SVR2_UTIL_CPU_H__

#include <stdint.h>

namespace svr2::util {

// `rdtsc` gets the current CPU ticks from the current CPU.
uint64_t asm_rdtsc();
inline uint64_t asm_rdtsc() {
  uint64_t lo, hi;
  asm volatile( "rdtsc" : "=a" (lo), "=d" (hi) );
  return lo | ( hi << 32 );
}

}  // namespace svr2::util

#endif  // __SVR2_UTIL_CPU_H__
