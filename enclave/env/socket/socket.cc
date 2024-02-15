// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdio.h>
#include <sys/random.h>
#include <sstream>
#include <chrono>
#include <signal.h>

#include "util/macros.h"
#include "util/endian.h"
#include "context/context.h"
#include "socketwrap/socket.h"
#include "proto/socketmain.pb.h"
#include "proto/enclaveconfig.pb.h"
#include "queue/queue.h"
#include "env/socket/socket.h"

namespace svr2::env::socket {
namespace {
static const char* SIMULATED_REPORT_PREFIX = "SEV_SIMULATED_REPORT:";

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

Environment::Environment(bool simulated) : simulated_(simulated) {}

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

error::Error Environment::RandomBytes(void* bytes, size_t size) const {
  uint8_t* u8ptr = reinterpret_cast<uint8_t*>(bytes);
  if (simulated_) {
    while (size) {
      auto out = getrandom(u8ptr, size, 0);
      if (out < 0) {
        return error::Env_RandomBytes;
      }
      size -= out;
      u8ptr += out;
    }
  } else {
    // This may be slow but uses direct CPU instructions to get randomness.
    // We're not sure we can trust syscalls, as they might be sent up
    // to the hypervisor or the host OS, both of which we may not have fully
    // verified.
    unsigned long long r;
    uint8_t buf[8];
    CHECK(sizeof(r) == sizeof(buf));
    while (size) {
      if (1 != __builtin_ia32_rdrand64_step(&r)) {
        return error::Env_RandomBytes;
      }
      util::BigEndian64Bytes(r, buf);
      for (size_t i = 0; i < sizeof(buf) && size; i++) {
        *u8ptr++ = buf[i];
        size--;
      }
    }
  }
  return error::OK;
}

std::pair<e2e::Attestation, error::Error> Environment::SimulatedEvidence(
    context::Context* ctx,
    const attestation::AttestationData& data) const {
  e2e::Attestation out;
  out.set_evidence(SIMULATED_REPORT_PREFIX + data.SerializeAsString());
  return std::make_pair(out, error::OK);
}

std::pair<attestation::AttestationData, error::Error> Environment::SimulatedAttest(
    context::Context* ctx,
    util::UnixSecs now,
    const e2e::Attestation& attestation) const {
  attestation::AttestationData out;
  if (attestation.evidence().rfind(SIMULATED_REPORT_PREFIX, 0) != 0) {
    return std::make_pair(out, error::Env_AttestationFailure);
  }
  size_t prefix_len = strlen(SIMULATED_REPORT_PREFIX);
  if (!out.ParseFromArray(attestation.evidence().data() + prefix_len, attestation.evidence().size() - prefix_len)) {
    return std::make_pair(out, error::Env_AttestationFailure);
  }
  return std::make_pair(out, error::OK);
}

}  // namespace svr2::env::socket
