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

Socket::Socket(int fd) : fd_(fd) {}

error::Error Socket::ReadAll(uint8_t* buf, size_t size) {
  while (size) {
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
    }
  }
  return error::OK;
}

error::Error Socket::WriteAll(uint8_t* buf, size_t size) {
  while (size) {
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
  ACQUIRE_LOCK(read_mu_, ctx, lock_socket_read);
  uint8_t uint32_buf[4] = {0};
  RETURN_IF_ERROR(ReadAll(uint32_buf, sizeof(uint32_buf)));
  size_t to_read = util::BigEndian32FromBytes(uint32_buf);
  if (to_read > INT32_MAX) {
    return COUNTED_ERROR(Socket_ReadTooBig);
  }
  LOG(VERBOSE) << "Reading " << to_read << " byte proto";
  if (read_buf_.size() < to_read) {
    read_buf_.resize(to_read);
  }
  RETURN_IF_ERROR(ReadAll(read_buf_.data(), to_read));
  if (!pb->ParseFromArray(read_buf_.data(), to_read)) {
    return COUNTED_ERROR(Socket_ParseIncoming);
  }
  return error::OK;
}

error::Error Socket::WritePB(context::Context* ctx, const google::protobuf::MessageLite& pb) {
  ACQUIRE_LOCK(write_mu_, ctx, lock_socket_write);
  size_t size = pb.ByteSizeLong();
  if (size > INT32_MAX) {
    return COUNTED_ERROR(Socket_WriteTooBig);
  }
  write_buf_.resize(size);
  uint8_t* end = pb.SerializeWithCachedSizesToArray(write_buf_.data());
  size = end - write_buf_.data();
  LOG(VERBOSE) << "Writing " << size << " byte proto";

  uint8_t uint32_buf[4] = {0};
  util::BigEndian32Bytes(size, uint32_buf);
  RETURN_IF_ERROR(WriteAll(uint32_buf, sizeof(uint32_buf)));
  RETURN_IF_ERROR(WriteAll(write_buf_.data(), size));
  return error::OK;
}

}  // namespace svr2::socketwrap
