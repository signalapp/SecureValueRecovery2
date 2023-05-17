// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <cstdlib>

#include "env/env.h"
#include "core/core.h"
#include "context/context.h"
#include "proto/enclaveconfig.pb.h"
#include "util/log.h"
#include "util/bytes.h"
#include "proto/nitro.pb.h"
#include "socketwrap/socket.h"
#include "env/nsm/nsm.h"
#include "queue/queue.h"

namespace svr2 {

#define RETURN_ERRNO_ERROR_UNLESS(x, err) do { \
  if (!(x)) { \
    int e = errno; \
    LOG(ERROR) << "(" << #x << ") evaluated to false, errno(" << e << "): " << strerror(e); \
    return COUNTED_ERROR(err); \
  } \
} while (0)

// To simplify our server, this function creates the appropriate
// AF_VSOCK, binds it, listens, accepts, then returns the accepted
// file descriptor, closing the listener.  We know that if this
// socket dies, we stop serving, so there's no need to create an
// accept loop.
error::Error AcceptSocket(bool simulated, int port, int* afd) {
  int fd;
  RETURN_ERRNO_ERROR_UNLESS(
      0 < (fd = socket(simulated ? AF_INET : AF_VSOCK, SOCK_STREAM, 0)),
      Nitro_SocketCreation);

  struct sockaddr* addr;
  socklen_t addr_size;

  struct sockaddr_vm vm_addr;
  struct sockaddr_in in_addr;
  if (simulated) {
    memset(&in_addr, 0, sizeof(in_addr));
    in_addr.sin_family = AF_INET;
    in_addr.sin_port = htons(port);
    in_addr.sin_addr.s_addr = INADDR_ANY;
    addr = reinterpret_cast<struct sockaddr*>(&in_addr);
    addr_size = sizeof(in_addr);
  } else {
    memset(&vm_addr, 0, sizeof(vm_addr));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_port = port;
    vm_addr.svm_cid = VMADDR_CID_ANY;
    addr = reinterpret_cast<struct sockaddr*>(&vm_addr);
    addr_size = sizeof(vm_addr);
  }
  LOG(INFO) << "Binding to port " << port;
  RETURN_ERRNO_ERROR_UNLESS(
      0 == bind(fd, addr, addr_size),
      Nitro_SocketBind);
  RETURN_ERRNO_ERROR_UNLESS(
      0 == listen(fd, 10),
      Nitro_SocketListen);

  *afd = 0;
  socklen_t initial_size = addr_size;
  while (*afd <= 0) {
    LOG(INFO) << "Accepting...";
    addr_size = initial_size;
    memset(addr, 0, addr_size);
    *afd = accept4(fd, addr, &addr_size, SOCK_CLOEXEC);
    RETURN_ERRNO_ERROR_UNLESS(
        *afd > 0 || errno == EINTR || errno == ECONNABORTED,
        Nitro_SocketAccept);
    uint8_t buf[1] = {0};
    auto got = recv(*afd, buf, 1, 0);
    if (got == 0) {
      LOG(INFO) << "Socket opened then closed without any data being sent, assuming a health check";
      close(*afd);
      *afd = 0;
    } else {
      RETURN_ERRNO_ERROR_UNLESS(got == 1, Nitro_SocketAccept);
      if (buf[0] != 'N') {
        LOG(ERROR) << "Missing nitro hello byte";
        return COUNTED_ERROR(Nitro_SocketAccept);
      }
      break;
    }
  }
  shutdown(fd, SHUT_RDWR);
  close(fd);
  LOG(INFO) << "Sucessfully accepted connection on FD=" << *afd;
  return error::OK;
}

error::Error RunServerThread(core::Core* core, socketwrap::Socket* sock) {
  while (true) {
    context::Context ctx;
    auto in = ctx.Protobuf<nitro::InboundMessage>();
    RETURN_IF_ERROR(sock->ReadPB(&ctx, in));
    if (in->inner_case() != nitro::InboundMessage::kMsg) {
      return COUNTED_ERROR(Nitro_InboundNotMessage);
    }
    auto msg = ctx.Protobuf<UntrustedMessage>();
    if (!msg->ParseFromString(in->mutable_msg()->data())) {
      return COUNTED_ERROR(Nitro_InboundMessageParse);
    }
    auto status = core->Receive(&ctx, *msg);
    auto out = ctx.Protobuf<nitro::OutboundMessage>();
    auto out_msg = out->mutable_msg();
    out_msg->set_id(in->msg().id());
    out_msg->set_status(status);
    RETURN_IF_ERROR(sock->WritePB(&ctx, *out));
  }
}

// Read an init message from a socket and use it to create a new core object.
std::pair<std::unique_ptr<core::Core>, error::Error> InitCore(socketwrap::Socket* sock, bool simulated) {
  context::Context ctx;
  auto pb = ctx.Protobuf<nitro::InboundMessage>();
  LOG(INFO) << "Reading init message";
  if (error::Error err = sock->ReadPB(&ctx, pb); err != error::OK) {
    return std::make_pair(nullptr, err);
  }
  if (pb->inner_case() != nitro::InboundMessage::kInit) {
    return std::make_pair(nullptr, COUNTED_ERROR(Nitro_InboundNotInit));
  }
  auto init = pb->init();
  if (init.initial_log_level() != enclaveconfig::LOG_LEVEL_NONE) {
    util::SetLogLevel(init.initial_log_level());
  }
  CHECK(init.group_config().simulated() == simulated);
  env::Init(init.group_config().simulated());
  LOG(INFO) << "Creating core";
  auto [core_ptr, err] = core::Core::Create(
      &ctx,
      init);
  if (err == error::OK) {
    LOG(INFO) << "Writing init message";
    auto out = ctx.Protobuf<nitro::OutboundMessage>();
    core_ptr->ID().ToString(out->mutable_init()->mutable_peer_id());
    err = sock->WritePB(&ctx, *out);
  }
  LOG(INFO) << "Core creation: " << err;
  return std::make_pair(std::move(core_ptr), err);
}

// Run a server, returning an error when it dies.
error::Error RunServer(bool simulated, int port) {
  int fd;
  RETURN_IF_ERROR(AcceptSocket(simulated, port, &fd));
  socketwrap::Socket sock(fd);
  auto sockp = &sock;
  std::vector<std::thread> threads;
  threads.emplace_back([sockp]{
    LOG(INFO) << "Starting thread to send NSM messages";
    LOG(FATAL) << env::nsm::SendNsmMessages(sockp);
  });
  auto [c, err] = InitCore(&sock, simulated);
  RETURN_IF_ERROR(err);
  auto cp = c.get();
  for (size_t i = 0; i < 32 /* chosen by random dice roll */; i++) {
    threads.emplace_back([cp, sockp]{
      LOG(FATAL) << RunServerThread(cp, sockp);
    });
  }
  for (size_t i = 0; i < threads.size(); i++) {
    threads[i].join();
  }
  return error::OK;  // unreachable
}

}  // namespace svr2

int main(int argc, char** argv) {
  bool simulated = false;
  int port = 27427;
  for (int i = 1; i < argc; i++) {
    std::string arg(argv[i]);
    if (arg == "--simulated") {
      simulated = true;
      LOG(INFO) << "Running in simulated mode";
      continue;
    } else if (arg.rfind("--port=", 0) == 0) {
      port = atoi(arg.data() + strlen("--port="));
      if (port > 0 && port < 65536) {
        continue;
      }
    }
    LOG(FATAL) << "Usage: " << argv[0]
        << " [--simulated]";
  }
  LOG(INFO) << "Running on port " << port << " with simulated=" << simulated;
  auto err = svr2::RunServer(simulated, port);
  LOG(FATAL) << err;
  return -1;
}
