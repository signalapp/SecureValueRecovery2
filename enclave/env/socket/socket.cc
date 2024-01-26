// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <chrono>
#include <signal.h>

#include "util/macros.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "proto/enclaveconfig.pb.h"
#include "queue/queue.h"
#include "env/socket/socket.h"

namespace svr2::env::socket {
namespace {

queue::Queue<socketmain::OutboundMessage> output_messages(256);

void LogFatalSignalHandler(int signal, siginfo_t* info, void* context) {
  LOG(FATAL) << "Crashing due to signal " << signal << " at addr " << reinterpret_cast<uintptr_t>(info->si_addr);
}

// Overrides signal handlers for SIGILL, SIGSEGV, and SIGFPE that
// calls LOG(FATAL).  This allows the information about these signals
// to make it up to operators in a more debuggable manner.
// LOG(FATAL) will eventually call `abort()` which will SIGABRT and crash.
class SignalsCauseFatalLogs {
 public:
  SignalsCauseFatalLogs();
  ~SignalsCauseFatalLogs();
  DELETE_COPY_AND_ASSIGN(SignalsCauseFatalLogs);
 private:
  struct sigaction orig_segv_;
  struct sigaction orig_fpe_;
  struct sigaction orig_ill_;
};

SignalsCauseFatalLogs::SignalsCauseFatalLogs() {
  LOG(INFO) << "Setting signal handlers to use LOG(FATAL)";
  struct sigaction new_handler;
  sigemptyset(&new_handler.sa_mask);
  new_handler.sa_handler = nullptr;
  new_handler.sa_flags = SA_SIGINFO;
  new_handler.sa_sigaction = &LogFatalSignalHandler;
  CHECK(0 == sigaction(SIGSEGV, &new_handler, &orig_segv_));
  CHECK(0 == sigaction(SIGFPE, &new_handler, &orig_fpe_));
  CHECK(0 == sigaction(SIGILL, &new_handler, &orig_ill_));
}
SignalsCauseFatalLogs::~SignalsCauseFatalLogs() {
  // Attempt to (but don't error check) reset handlers.
  sigaction(SIGSEGV, &orig_segv_, nullptr);
  sigaction(SIGFPE, &orig_fpe_, nullptr);
  sigaction(SIGILL, &orig_ill_, nullptr);
}

SignalsCauseFatalLogs signals_cause_fatal_logs;

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
