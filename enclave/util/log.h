// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_LOG_H__
#define __SVR2_UTIL_LOG_H__

#include <ostream>
#include <sstream>
#include <thread>
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"

std::ostream& operator<<(std::ostream& os, ::svr2::error::Error err);

namespace svr2::util {

class Log {
 public:
  Log(::svr2::enclaveconfig::EnclaveLogLevel lvl);
  ~Log();

  template <class T>
  std::ostream& operator<<(T x) {
    ss_ << x;
    return ss_;
  }

 private:
  ::svr2::enclaveconfig::EnclaveLogLevel lvl_;
  std::stringstream ss_;
};

extern ::svr2::enclaveconfig::EnclaveLogLevel log_level_to_write;
extern std::hash<std::thread::id> thread_id_hasher;

void SetLogLevel(::svr2::enclaveconfig::EnclaveLogLevel level);

uint64_t TimestampMicros();

}  // namespace svr2::util

#define LOG(x) if (::svr2::enclaveconfig::LOG_LEVEL_##x <= ::svr2::util::log_level_to_write) ::svr2::util::Log(::svr2::enclaveconfig::LOG_LEVEL_##x) << #x << "\t" << __FILE__ << ":" << __LINE__ << "(" << __FUNCTION__ << ") @ " << ::svr2::util::TimestampMicros() << " T=" << (::svr2::util::thread_id_hasher(std::this_thread::get_id()) % 10000) << " - "

#endif  // __SVR2_UTIL_LOG_H__
