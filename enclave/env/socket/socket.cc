// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>

#include "util/macros.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "queue/queue.h"
#include "env/socket/socket.h"

namespace svr2::env::socket {
namespace {

static queue::Queue<socketmain::OutboundMessage> output_messages(256);

}  // namespace

Environment::Environment() {}

Environment::~Environment() {}

error::Error Environment::SendMessage(const std::string& msg) const {
  socketmain::OutboundMessage out;
  out.set_out(msg);
  output_messages.Push(std::move(out));
  return error::OK;
}

void Environment::Log(int level, const std::string& msg) const {
  fprintf(stderr, "env::NSM LOG(%d): %s\n", level, msg.c_str());
  socketmain::OutboundMessage out;
  out.mutable_log()->set_log(msg);
  out.mutable_log()->set_level((::svr2::enclaveconfig::EnclaveLogLevel) level);
  output_messages.Push(std::move(out));
}

error::Error SendSocketMessages(socketwrap::Socket* sock) {
  while (true) {
    context::Context ctx;
    for (int i = 0; i < 100; i++) {
      auto out = output_messages.Pop();
      RETURN_IF_ERROR(sock->WritePB(&ctx, out));
    }
  }
}

}  // namespace svr2::env::socket
