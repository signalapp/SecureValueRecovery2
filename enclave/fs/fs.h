// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_FS_FS_H__
#define __SVR2_FS_FS_H__

#include <string>
#include <utility>
#include "proto/error.pb.h"
#include "util/macros.h"

namespace svr2::fs {

std::pair<std::string, error::Error> FileContents(const std::string& filename);

class TmpDir {
 public:
  DELETE_COPY_AND_ASSIGN(TmpDir);
  TmpDir() : name_("") {}
  TmpDir(TmpDir&& other) {
    name_ = other.name_;
    other.name_ = "";
  }
  ~TmpDir();
  error::Error Init();
  const std::string& name() { return name_; }
 private:
  std::string name_;
};

}  // namespace svr2::fs

#endif  // __SVR2_FS_FS_H__
