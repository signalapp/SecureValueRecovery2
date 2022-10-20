// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_MACROS_H__
#define __SVR2_UTIL_MACROS_H__

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "CHECK FAIL @ %s:%d in %s: %s\n", __FILE__, __LINE__, __FUNCTION__, #x); \
    abort(); \
  } \
} while (0)

#define RETURN_IF_ERROR(x) do { \
  ::svr2::error::Error _err_ = (x); \
  if (_err_ != ::svr2::error::OK) return _err_; \
} while (0)

#define DELETE_COPY_AND_ASSIGN(x) \
  x(x& other) = delete; \
  void operator=(const x &) = delete
#define DELETE_ASSIGN(x) \
  void operator=(const x &) = delete

#ifdef IS_TEST
#define public_for_test public
#else
#define public_for_test private
#endif

#endif  // __SVR2_UTIL_MACROS_H__
