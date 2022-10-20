// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SOCKET_SOCKET_H__
#define __SVR2_SOCKET_SOCKET_H__

#include <google/protobuf/message_lite.h>
#include "proto/error.pb.h"
#include "context/context.h"
#include "util/mutex.h"

#include <vector>

namespace svr2::socketwrap {

class Socket {
 public:
  Socket(int fd);  // `fd` should already be bound/listening.

  error::Error ReadPB(context::Context* ctx, google::protobuf::MessageLite* pb) EXCLUDES(read_mu_);
  error::Error WritePB(context::Context* ctx, const google::protobuf::MessageLite& pb) EXCLUDES(write_mu_);

 public_for_test:
  error::Error ReadAll(uint8_t* buf, size_t size);
  error::Error WriteAll(uint8_t* buf, size_t size);
 
 private:
  int fd_;
  util::mutex read_mu_;
  util::mutex write_mu_;
  // Reusable buffers for reading/writing.  Will grow to be the max size
  // of all messages they've seen.
  std::vector<uint8_t> read_buf_ GUARDED_BY(read_mu_);
  std::vector<uint8_t> write_buf_ GUARDED_BY(write_mu_);
};

}  // namespace svr2::socketwrap

#endif  // __SVR2_SOCKET_SOCKET_H__
