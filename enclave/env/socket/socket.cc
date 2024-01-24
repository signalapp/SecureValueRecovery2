// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <chrono>

#include "util/macros.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "proto/enclaveconfig.pb.h"
#include "queue/queue.h"
#include "env/socket/socket.h"

namespace svr2::env::socket {
namespace {

static queue::Queue<socketmain::OutboundMessage> output_messages(256);

}  // namespace

Environment::Environment() {}

Environment::~Environment() {}

error::Error Environment::SendMessage(context::Context* ctx, const std::string& msg) const {
  MEASURE_CPU(ctx, cpu_env_sendmessage);
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

void Environment::FlushAllLogsIfAble() const {
  // queue->Flush waits for all current messages to be popped.  A message won't
  // be popped until the previous message has been written to the socket.  So,
  // we add a new message onto the queue, then Flush to make sure everything
  // before (and possibly including) the pushed output_message has made it out
  // from the socket.
  Log(::svr2::enclaveconfig::EnclaveLogLevel::LOG_LEVEL_ERROR, "FlushAllLogsIfAble");
  output_messages.Flush(5000);
}

error::Error SendSocketMessages(socketwrap::Socket* sock) {
  while (true) {
    context::Context ctx;
    for (int i = 0; i < 100; i++) {
      IGNORE_CPU(&ctx);
      auto out = output_messages.Pop();
      RETURN_IF_ERROR(sock->WritePB(&ctx, out));
    }
  }
}

}  // namespace svr2::env::socket
