// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/bytes.h"

namespace svr2::util {

void MemZeroS(void* data, size_t size) {
  // This follows the same pattern used in noise-c/src/util.c's noise_clean.
  volatile uint8_t *d = reinterpret_cast<volatile uint8_t *>(data);
  while (size > 0) {
    *d++ = 0;
    --size;
  }
  // The following does nothing, but the compiler can't read inside and
  // see that, so it has to assume this function causes some unknown
  // side effects.  Because of that, the compiler cannot remove calls to
  // this function as part of optimization.
  asm("");
}

}  // namespace svr2::util
