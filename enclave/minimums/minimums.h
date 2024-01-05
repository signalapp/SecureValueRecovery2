// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_WATERMARKS_WATERMARKS_H__
#define __SVR2_WATERMARKS_WATERMARKS_H__

#include <unordered_map>
#include "proto/minimums.pb.h"
#include "proto/error.pb.h"
#include "util/mutex.h"
#include "util/bytes.h"
#include "util/endian.h"
#include "context/context.h"

namespace svr2::minimums {

class Minimums {
 public:
  Minimums() {}
  Minimums(const Minimums& cpy) {
    util::unique_lock cl(cpy.mu_);
    s_.MergeFrom(cpy.s_);
  }
  error::Error UpdateLimits(context::Context* ctx, const MinimumLimits& s);
  error::Error CheckValues(context::Context* ctx, const MinimumValues& values) const;
  static std::string U64(uint64_t value) {
    std::string v(8, '\0');
    util::BigEndian64Bytes(value, reinterpret_cast<uint8_t*>(v.data()));
    return v;
  }
  // CombineMin combines two MinimumValues.  In cases where both have the same
  // key, the minimum value is returned.  Note that we choose the minimum
  // because this is _values_ we're combining.
  static MinimumValues CombineValues(const MinimumValues& a, const MinimumValues& b);
 private:
  static error::Error CheckValuesAgainstSet(const MinimumLimits& s, const MinimumValues& values);
  static error::Error CheckValueAgainstSet(const MinimumLimits& s, const std::string& key, const std::string& value);

  mutable util::mutex mu_;
  MinimumLimits s_ GUARDED_BY(mu_);
};

}  // namespace svr2::minimums

#endif  // __SVR2_WATERMARKS_WATERMARKS_H__
