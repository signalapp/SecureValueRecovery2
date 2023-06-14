// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "env/env.h"
#include "proto/enclaveconfig.pb.h"
#include "util/log.h"

int main(int argc, char** argv) {
  svr2::util::SetLogLevel(svr2::enclaveconfig::LOG_LEVEL_VERBOSE);
  svr2::env::Init(svr2::env::NOT_SIMULATED);
}
