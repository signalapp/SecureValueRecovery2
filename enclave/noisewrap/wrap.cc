// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "env/env.h"
#include "proto/error.pb.h"
#include "util/macros.h"
#include "context/context.h"

extern "C" {

// Wrap Noise's call to get randomness so it uses our enclave's random generator.
void __wrap_noise_rand_bytes(void* bytes, size_t size) {
  CHECK(::svr2::error::OK == ::svr2::env::environment->RandomBytes(bytes, size));
}

}  // extern "C"
