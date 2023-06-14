// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_SOCKET_SOCKET_H__
#define __SVR2_ENV_SOCKET_SOCKET_H__

#include "socketwrap/socket.h"
#include "proto/error.pb.h"
#include "env/env.h"

namespace svr2::env::socket {

class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment();
  virtual ~Environment();
  virtual error::Error SendMessage(const std::string& msg) const;
  virtual void Log(int level, const std::string& msg) const;
};

// Send all outstanding messages, in order, up to the host.
// Blocks forever.
error::Error SendSocketMessages(socketwrap::Socket* sock);

}  // namespace svr2::env::nsm

#endif  // __SVR2_ENV_SOCKET_SOCKET_H__
