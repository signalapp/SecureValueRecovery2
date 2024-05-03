// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "minimums/minimums.h"
#include "util/macros.h"
#include "util/log.h"
#include "util/hex.h"

namespace svr2::minimums {

error::Error Minimums::UpdateLimits(context::Context* ctx, const MinimumLimits& s) {
  ACQUIRE_LOCK(mu_, ctx, lock_minimums_updateset);
  for (const auto& iter : s_.lim()) {
    if (s.lim().count(iter.first) == 0) {
      return error::Minimums_KeyMissing;
    }
  }
  for (const auto& iter : s.lim()) {
    if (iter.second.size() == 0) {
      return error::Minimums_EntryEmpty;
    } else if (iter.first == "") {
      return error::Minimums_KeyEmpty;
    }
    auto finder = s_.lim().find(iter.first);
    if (finder == s_.lim().end()) {
      continue;
    }
    const auto& v_old = finder->second;
    const auto& v_new = iter.second;
    if (v_old > v_new) {
      return error::Minimums_LimitDecreased;
    } else if (v_old.size() != v_new.size()) {
      return error::Minimums_SizeMismatch;
    }
  }
  s_ = s;
  for (const auto& iter : s.lim()) {
    LOG(INFO) << "Minimums update: '" << iter.first << "' = 0x" << util::ToHex(iter.second);
  }
  return error::OK;
}

error::Error Minimums::CheckValuesAgainstSet(const MinimumLimits& s, const MinimumValues& v) {
  for (const auto& iter : v.val()) {
    RETURN_IF_ERROR(CheckValueAgainstSet(s, iter.first, iter.second));
  }
  return error::OK;
}

error::Error Minimums::CheckValues(context::Context* ctx, const MinimumValues& v) const {
  ACQUIRE_LOCK(mu_, ctx, lock_minimums_checkvalues);
  return CheckValuesAgainstSet(s_, v);
}

error::Error Minimums::CheckValueAgainstSet(const MinimumLimits& s, const std::string& key, const std::string& value) {
  auto finder = s.lim().find(key);
  if (finder == s.lim().end()) {
    return error::OK;
  }
  const auto& limit = finder->second;
  if (value < limit) {
    return error::Minimums_ValueTooLow;
  } else if (value.size() != limit.size()) {
    return error::Minimums_ValueSize;
  }
  return error::OK;
}

void Minimums::CombineValues(const MinimumValues& from, MinimumValues* into) {
  for (auto iter = from.val().begin(); iter != from.val().end(); ++iter) {
    auto finder = into->val().find(iter->first);
    if (finder == into->val().end() || finder->second > iter->second) {
      (*into->mutable_val())[iter->first] = iter->second;
    }
  }
}

}  // namespace svr2::minimums

std::ostream& operator<<(std::ostream& os, const svr2::minimums::MinimumValues& val) {
  os << "MIN_VAL{";
  for (auto iter : val.val()) {
    os << " " << iter.first << "=0x" << svr2::util::ToHex(iter.second);
  }
  os << " }";
  return os;
}
std::ostream& operator<<(std::ostream& os, const svr2::minimums::MinimumLimits& lim) {
  os << "MIN_LIM{";
  for (auto iter : lim.lim()) {
    os << " " << iter.first << "=0x" << svr2::util::ToHex(iter.second);
  }
  os << " }";
  return os;
}
std::ostream& operator<<(std::ostream& os, const svr2::minimums::Minimums& min) {
  svr2::util::unique_lock lock(min.mu_);
  os << min.s_;
  return os;
}
