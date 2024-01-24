// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "util/log.h"
#include "env/env.h"
#include "util/macros.h"
#include <sys/time.h>
#include <stdlib.h>

namespace svr2::util {

::svr2::enclaveconfig::EnclaveLogLevel log_level_to_write =
#ifdef IS_TEST
  enclaveconfig::LOG_LEVEL_MAX;
#else
  enclaveconfig::LOG_LEVEL_INFO;
#endif

std::hash<std::thread::id> thread_id_hasher;

Log::Log(::svr2::enclaveconfig::EnclaveLogLevel lvl) : lvl_(lvl) {}

Log::~Log() {
  env::environment->Log(lvl_, ss_.str());
  if (lvl_ == enclaveconfig::LOG_LEVEL_FATAL) {
    env::environment->FlushAllLogsIfAble();
    abort();
  }
}

void SetLogLevel(::svr2::enclaveconfig::EnclaveLogLevel level) {
  log_level_to_write = level;
}

uint64_t TimestampMicros() {
  struct timeval tv;
  if (0 != gettimeofday(&tv, NULL)) return -1;
  return tv.tv_usec + (1000000 * tv.tv_sec);
}

}  // namespace svr2::util

std::ostream& operator<<(std::ostream& os, ::svr2::error::Error err) {
  if (err == ::svr2::error::OK) {
    os << "OK";
  } else {
    os << "error::" << ::svr2::error::Error_Name(err);
  }
  return os;
}
