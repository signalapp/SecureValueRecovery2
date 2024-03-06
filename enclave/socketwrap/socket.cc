// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include "socketwrap/socket.h"

#include "context/context.h"
#include "util/log.h"
#include "util/endian.h"

namespace svr2::socketwrap {

namespace {
const size_t write_buffer_size_limit = 100 << 20;  // 100MB
}  // namespace

Socket::Socket(int fd) : fd_(fd) {}

error::Error Socket::ReadAll(uint8_t* buf, size_t size) {
  while (size) {
    COUNTER(socketwrap, recv_calls)->IncrementBy(1);
    ssize_t got = recv(fd_, buf, size, 0);
    if (got == 0) {
      return COUNTED_ERROR(Socket_ReadEOF);
    } else if (got < 0) {
      switch (errno) {
        case EINTR:
          continue;
        default:
          LOG(ERROR) << "Socket " << fd_ << " recv error: " << errno << " - " << strerror(errno);
          return COUNTED_ERROR(Socket_Read);
      }
    } else {
      size -= got;
      buf += got;
      COUNTER(socketwrap, bytes_read)->IncrementBy(got);
    }
  }
  return error::OK;
}

error::Error Socket::WriteAll(uint8_t* buf, size_t size) {
  while (size) {
    COUNTER(socketwrap, send_calls)->IncrementBy(1);
    ssize_t got = send(fd_, buf, size, MSG_NOSIGNAL);
    if (got < 0) {
      switch (errno) {
        case EINTR:
          continue;
        default:
          LOG(ERROR) << "Socket " << fd_ << " send error: " << errno << " - " << strerror(errno);
          return COUNTED_ERROR(Socket_Write);
      }
    } else {
      size -= got;
      buf += got;
    }
  }
  return error::OK;
}

error::Error Socket::ReadPB(context::Context* ctx, google::protobuf::MessageLite* pb) {
  util::unique_lock read_lock(read_mu_, std::defer_lock);
  {
    IGNORE_CPU(ctx);
    read_lock.lock();
  }
  size_t to_read = 0;
  {
    IGNORE_CPU(ctx);
    uint8_t uint32_buf[4] = {0};
    RETURN_IF_ERROR(ReadAll(uint32_buf, sizeof(uint32_buf)));
    to_read = util::BigEndian32FromBytes(uint32_buf);
    if (to_read > INT32_MAX) {
      return COUNTED_ERROR(Socket_ReadTooBig);
    }
    LOG(VERBOSE) << "Reading " << to_read << " byte proto";
    MEASURE_CPU(ctx, cpu_socket_read_recv);
    if (read_buf_.size() < to_read) {
      read_buf_.resize(to_read);
    }
    RETURN_IF_ERROR(ReadAll(read_buf_.data(), to_read));
  }
  COUNTER(socketwrap, msgs_read)->IncrementBy(1);
  {
    MEASURE_CPU(ctx, cpu_socket_read_parse);
    if (!pb->ParseFromArray(read_buf_.data(), to_read)) {
      return COUNTED_ERROR(Socket_ParseIncoming);
    }
  }
  return error::OK;
}

WriteQueue::WriteQueue()
    : current_buffer_(&buffers_[1]), done_(false), in_use_(false), writes_(0) {
  buffers_[0].reserve(1 << 20);
  buffers_[1].reserve(1 << 20);
}

error::Error WriteQueue::WritePB(context::Context* ctx, const google::protobuf::MessageLite& pb) {
  if (!pb.IsInitialized()) {
    return COUNTED_ERROR(Socket_WriteNotInitialized);
  }
  size_t size = pb.ByteSizeLong();
  if (size > INT32_MAX) {
    return COUNTED_ERROR(Socket_WriteTooBig);
  }
  {
    std::unique_lock lock(mu_, std::defer_lock);
    {
      MEASURE_CPU(ctx, lock_socket_write);
      lock.lock();
    }
    size_t total_size = size + 4;
    size_t start = current_buffer_->size();
    current_buffer_->resize(start + total_size);
    util::BigEndian32Bytes(size, current_buffer_->data() + start);
    {
      MEASURE_CPU(ctx, cpu_socket_write_serialize);
      uint8_t* end = pb.SerializeWithCachedSizesToArray(current_buffer_->data() + start + 4);
      CHECK(end == current_buffer_->data() + current_buffer_->size());
    }
    GAUGE(socketwrap, output_buffer_size)->Set(buffers_[0].size() + buffers_[1].size());
    GAUGE(socketwrap, output_buffer_cap)->Set(buffers_[0].capacity() + buffers_[1].capacity());
  }
  COUNTER(socketwrap, msgs_written)->IncrementBy(1);
  to_write_.notify_all();
  return error::OK;
}

std::vector<uint8_t>* WriteQueue::OtherBuffer(std::vector<uint8_t>* b) {
  if (b == &buffers_[0]) {
    return &buffers_[1];
  } else if (b == &buffers_[1]) {
    return &buffers_[0];
  }
  CHECK(nullptr == "OtherBuffer called not with one of the owned buffers");
  return nullptr;
}

error::Error WriteQueue::WriteThread(Socket* s) {
  bool expected = false;
  CHECK(in_use_.compare_exchange_strong(expected, true));
  util::unique_lock lock(s->write_mu_);
  context::Context ctx;
  IGNORE_CPU(&ctx);
  while (true) {
    written_.notify_all();
    std::vector<uint8_t>* write_buffer = nullptr;
    {
      // Get a non-empty buffer ...
      std::unique_lock lock(mu_, std::defer_lock);
      {
        MEASURE_CPU(&ctx, lock_socket_write);
        lock.lock();
      }
      while (current_buffer_->size() == 0 && !done_.load()) {
        to_write_.wait(lock);
      }
      if (done_.load() && current_buffer_->size() == 0) {
        expected = true;
        CHECK(in_use_.compare_exchange_strong(expected, false));
        return error::OK;
      }
      write_buffer = current_buffer_;
      // ... and switch to writing new messages to the other buffer ...
      current_buffer_ = OtherBuffer(current_buffer_);
      CHECK(current_buffer_->size() == 0);
      CHECK(write_buffer->size() > 0);
      CHECK(current_buffer_ != write_buffer);
      // ... at which point we can unlock the write_lock so that
      // other threads can start filling up the new current_buffer_.
    }
    // Write the entire buffer we have to the socket.
    RETURN_IF_ERROR(s->WriteAll(write_buffer->data(), write_buffer->size()));
    COUNTER(socketwrap, writeall_calls)->IncrementBy(1);
    COUNTER(socketwrap, bytes_written)->IncrementBy(write_buffer->size());

    std::unique_lock lock(mu_, std::defer_lock);
    {
      MEASURE_CPU(&ctx, lock_socket_write);
      lock.lock();
    }
    // Resize capacity down if necessary.
    if (write_buffer->size() > write_buffer_size_limit) {
      // We can't say "shrink to size X", but we can say "shrink to
      // current size", so we temporarily resize to the size we want
      // to shrink to.
      write_buffer->resize(write_buffer_size_limit);
      write_buffer->shrink_to_fit();
      COUNTER(socketwrap, write_buffer_shrinks)->IncrementBy(1);
    }
    // Clear the buffer.
    write_buffer->resize(0);
    writes_++;
  }
}

void WriteQueue::KillThread() {
  done_.store(true);
  to_write_.notify_all();
}

void WriteQueue::FlushIfAble(int millis) {
  std::unique_lock lock(mu_);
  auto curr = current_buffer_;
  auto other = OtherBuffer(curr);
  auto wait_for_writes = writes_;
  if (curr->size()) wait_for_writes++;
  if (other->size()) wait_for_writes++;
  written_.wait_for(
      lock, std::chrono::milliseconds(millis), [this, wait_for_writes]{
        return writes_ >= wait_for_writes;
      });
}

}  // namespace svr2::socketwrap
