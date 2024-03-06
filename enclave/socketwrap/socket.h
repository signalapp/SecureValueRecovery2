// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SOCKET_SOCKET_H__
#define __SVR2_SOCKET_SOCKET_H__

#include <google/protobuf/message_lite.h>
#include <condition_variable>
#include <atomic>
#include "proto/error.pb.h"
#include "context/context.h"
#include "util/mutex.h"

#include <vector>

namespace svr2::socketwrap {

class Socket;

// WriteQueue handles writing protobufs to a single Socket.
// Only one WriteQueue should be associated with only one Socket.
//
// This class attempts to minimize the number of `send()` calls
// the socket needs to make, by appending all incoming protobufs
// to a buffer, then writing that buffer all at once.  Contains two
// buffers; one will always be available for writing into, while
// the other is `send()`ing.
class WriteQueue {
 public:
  WriteQueue();
  DELETE_COPY_AND_ASSIGN(WriteQueue);
  error::Error WritePB(context::Context* ctx, const google::protobuf::MessageLite& pb);

  // WriteThread blocks forever, sending all protobufs from `WritePB` calls
  // to the given socket.  Returns an error if it runs into issues writing.
  error::Error WriteThread(Socket* s);

  // FlushIfAble attempts to block for `millis` milliseconds or until the last
  // call to WritePB is written to the socket, whichever comes first.
  void FlushIfAble(int millis);

 public_for_test:
  // Stop the current WriteThread call.
  void KillThread();
 private:
  error::Error WriteNext();
  std::vector<uint8_t>* OtherBuffer(std::vector<uint8_t>* b);

  std::mutex mu_;
  std::condition_variable to_write_;  // notified when there is data to write
  std::condition_variable written_;  // notified when data has been written

  // Two write buffers.  Data is written to one (the `current_buffer_`).  When
  // the WriteThread notices that the `current_buffer_` has data, it switches
  // `current_buffer_` to point to the other one, then writes the buffer with
  // data in it to a socket.  While it's writing, the new `current_buffer_` is
  // filled with data, and will be written next.
  std::vector<uint8_t> buffers_[2];  

  std::vector<uint8_t>* current_buffer_;  // points at either buffers_[0] or buffers_[1]
  std::atomic<bool> done_;
  std::atomic<bool> in_use_;  // enforces single-use of this object's WriteThread call.
  uint64_t writes_;
};

class Socket {
 public:
  Socket(int fd);  // `fd` should already be bound/listening.

  error::Error ReadPB(context::Context* ctx, google::protobuf::MessageLite* pb) EXCLUDES(read_mu_);

 public_for_test:
  error::Error ReadAll(uint8_t* buf, size_t size);
  error::Error WriteAll(uint8_t* buf, size_t size);  // called by WriteQueue
 
 private:
  friend class WriteQueue;
  int fd_;
  util::mutex read_mu_;
  util::mutex write_mu_;
  // Reusable buffers for reading/writing.  Will grow to be the max size
  // of all messages they've seen.
  std::vector<uint8_t> read_buf_ GUARDED_BY(read_mu_);
};

}  // namespace svr2::socketwrap

#endif  // __SVR2_SOCKET_SOCKET_H__
