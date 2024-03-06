// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_MUTEX_H__
#define __SVR2_UTIL_MUTEX_H__

#include <mutex>
#include "util/threadsafetyannotations.h"
#include "util/macros.h"

namespace svr2::util {

// These classes are simple wrappers around equivalent std::xxx classes,
// except they've been augmented with Clang thread safety annotations
// for static analysis of locking.

class CAPABILITY("mutex") mutex {
 public:
  DELETE_COPY_AND_ASSIGN(mutex);
  mutex() {}
  inline void lock() ACQUIRE() { mu_.lock(); }
  inline void unlock() RELEASE() { mu_.unlock(); }
  inline bool try_lock() TRY_ACQUIRE(true) { return mu_.try_lock(); }

  // For negative thread safety analysis capabilities only.
  const mutex& operator!() const {
    CHECK(nullptr == "this function should be used only for thread annotations");
    return *this;
  }

 private:
   std::mutex mu_;
};

template <class T>
class SCOPED_CAPABILITY unique_lock {
 public:
  DELETE_COPY_AND_ASSIGN(unique_lock);
  unique_lock(T& mu) ACQUIRE(mu) : mu_(mu), locked_(true) { mu_.lock(); }
  ~unique_lock() RELEASE() { if (locked_) mu_.unlock(); }
  unique_lock(T& mu, std::defer_lock_t d) EXCLUDES(mu) : mu_(mu), locked_(false) { }
  inline void lock() ACQUIRE() { mu_.lock(); locked_ = true; }
  inline void unlock() RELEASE() { mu_.unlock(); locked_ = false; }

 private:
  T& mu_;
  bool locked_;
};

}  // namespace svr2::util

#endif  // __SVR2_UTIL_MUTEX_H__
