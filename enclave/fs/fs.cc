// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "fs/fs.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fts.h>

#include "metrics/metrics.h"
#include "util/log.h"
#include "env/env.h"
#include "util/hex.h"

namespace svr2::fs {

std::pair<std::string, error::Error> FileContents(const std::string& filename) {
  int fd = open(filename.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd <= 0) {
    LOG(ERROR) << "Opening file '" << filename << "' for read: " << strerror(errno);
    return std::make_pair("", COUNTED_ERROR(FS_OpenFile));
  }
  char buf[64];
  ssize_t ret = -1;
  std::string out;
  while (0 < (ret = read(fd, buf, sizeof(buf)))) {
    out.append(buf, static_cast<size_t>(ret));
  }
  if (ret < 0) {
    LOG(ERROR) << "Reading file '" << filename << "': " << strerror(errno);
    close(fd);
    return std::make_pair("", COUNTED_ERROR(FS_OpenFile));
  }
  close(fd);
  return std::make_pair(std::move(out), error::OK);
}

error::Error TmpDir::Init() {
  if (name_ != "") {
    return COUNTED_ERROR(FS_TmpDirAlreadyInitiated);
  }
  std::array<uint8_t, 8> bytes;
  TmpDir out;
  if (auto err = env::environment->RandomBytes(bytes.data(), bytes.size()); err != error::OK) {
    return err;
  }
  std::string name = "/tmp/svr." + util::ToHex(bytes);
  if (int ret = mkdir(name.c_str(), 0700); ret != 0) {
    LOG(ERROR) << "Making temp directory failed: " << strerror(errno);
    return COUNTED_ERROR(FS_Mkdir);
  }
  LOG(DEBUG) << "New temp directory: " << name;
  name_ = name;
  return error::OK;
}

TmpDir::~TmpDir() {
  if (name_ == "") return;
  LOG(DEBUG) << "Recursively deleting directory " << name_;
  const char* files[] = {name_.c_str(), nullptr};
  FTS* fts = fts_open(const_cast<char *const *>(files), FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
  if (!fts) {
    LOG(ERROR) << "Error recursively deleting '" << name_ << "'";
    return;
  }
  FTSENT* curr;
  while (nullptr != (curr = fts_read(fts))) {
    switch (curr->fts_info) {
      case FTS_D:  // directory, in pre-order
        break;
      case FTS_DP:  // directory, in post-order
      case FTS_F:   // normal file
        LOG(DEBUG) << " rm " << curr->fts_accpath;
        if (int ret = remove(curr->fts_accpath); ret != 0) {
          LOG(ERROR) << "Error deleting file '" << curr->fts_accpath << "' in temp directory '" << name_ << "': " << strerror(errno);
        }
        break;
      default:
        LOG(ERROR) << "Unable to handle deletion of file '" << curr->fts_accpath << "' in temp directory '" << name_ << "'";
    }
  }
}

}  // namespace svr2::fs
