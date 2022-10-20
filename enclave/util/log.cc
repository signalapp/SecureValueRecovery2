// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/log.h"
#include "env/env.h"
#include "util/macros.h"

namespace svr2::util {

::svr2::enclaveconfig::EnclaveLogLevel log_level_to_write =
#ifdef IS_TEST
  enclaveconfig::LOG_LEVEL_MAX;
#else
  enclaveconfig::LOG_LEVEL_INFO;
#endif

Log::Log(::svr2::enclaveconfig::EnclaveLogLevel lvl) : lvl_(lvl) {}

Log::~Log() {
  env::environment->Log(lvl_, ss_.str());
  if (lvl_ == enclaveconfig::LOG_LEVEL_FATAL) { CHECK(false); }
}

void SetLogLevel(::svr2::enclaveconfig::EnclaveLogLevel level) {
  log_level_to_write = level;
}

}  // namespace svr2::util

std::ostream& operator<<(std::ostream& os, ::svr2::error::Error err) {
  os << ::svr2::error::Error_Name(err);
  return os;
}
