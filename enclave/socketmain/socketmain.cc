// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include "proto/socketmain.pb.h"
#include "socketwrap/socket.h"
#include "env/socket/socket.h"
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
error::Error AcceptSocket(int sock_type, int port, int* afd) {
  int fd;
  RETURN_ERRNO_ERROR_UNLESS(
      0 < (fd = socket(sock_type, SOCK_STREAM, 0)),
      SocketMain_SocketCreation);

  struct sockaddr* addr;
  socklen_t addr_size;

  struct sockaddr_vm vm_addr;
  struct sockaddr_in in_addr;
  switch (sock_type) {
    case AF_INET:
      memset(&in_addr, 0, sizeof(in_addr));
      in_addr.sin_family = AF_INET;
      in_addr.sin_port = htons(port);
      in_addr.sin_addr.s_addr = INADDR_ANY;
      addr = reinterpret_cast<struct sockaddr*>(&in_addr);
      addr_size = sizeof(in_addr);
      break;
    case AF_VSOCK:
      memset(&vm_addr, 0, sizeof(vm_addr));
      vm_addr.svm_family = AF_VSOCK;
      vm_addr.svm_port = port;
      vm_addr.svm_cid = VMADDR_CID_ANY;
      addr = reinterpret_cast<struct sockaddr*>(&vm_addr);
      addr_size = sizeof(vm_addr);
      break;
    default:
      return COUNTED_ERROR(SocketMain_UnsupportedSockType);
  }
  LOG(INFO) << "Binding to port " << port;
  RETURN_ERRNO_ERROR_UNLESS(
      0 == bind(fd, addr, addr_size),
      SocketMain_SocketBind);
  RETURN_ERRNO_ERROR_UNLESS(
      0 == listen(fd, 10),
      SocketMain_SocketListen);

  *afd = 0;
  socklen_t initial_size = addr_size;
  while (*afd <= 0) {
    LOG(INFO) << "Accepting...";
    addr_size = initial_size;
    memset(addr, 0, addr_size);
    *afd = accept4(fd, addr, &addr_size, SOCK_CLOEXEC);
    RETURN_ERRNO_ERROR_UNLESS(
        *afd > 0 || errno == EINTR || errno == ECONNABORTED,
        SocketMain_SocketAccept);
    uint8_t buf[1] = {0};
    auto got = recv(*afd, buf, 1, 0);
    if (got == 0) {
      LOG(INFO) << "Socket opened then closed without any data being sent, assuming a health check";
      close(*afd);
      *afd = 0;
    } else {
      RETURN_ERRNO_ERROR_UNLESS(got == 1, SocketMain_SocketAccept);
      if (buf[0] != 'N') {
        LOG(ERROR) << "Missing socketmain hello byte";
        return COUNTED_ERROR(SocketMain_SocketAccept);
      }
      break;
    }
  }
  shutdown(fd, SHUT_RDWR);
  close(fd);
  if (sock_type == AF_INET) {
    int tcp_nodelay = 1;
    RETURN_ERRNO_ERROR_UNLESS(
        0 == setsockopt(*afd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay)),
        SocketMain_SocketSetOpt);
    int tcp_keepalive = 1;
    int tcp_keepalive_idle = 60;  // send first probe after 1m of inactivity
    int tcp_keepalive_intvl = 30;  // send subsequent probes every 30s
    int tcp_keepalive_cnt = 8;  // fail if 8 probes are unack'd.  This totals ~5m of total time
    RETURN_ERRNO_ERROR_UNLESS(
        0 == setsockopt(*afd, SOL_SOCKET, SO_KEEPALIVE, &tcp_keepalive, sizeof(tcp_keepalive)),
        SocketMain_SocketSetOpt);
    RETURN_ERRNO_ERROR_UNLESS(
        0 == setsockopt(*afd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepalive_idle, sizeof(tcp_keepalive_idle)),
        SocketMain_SocketSetOpt);
    RETURN_ERRNO_ERROR_UNLESS(
        0 == setsockopt(*afd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl)),
        SocketMain_SocketSetOpt);
    RETURN_ERRNO_ERROR_UNLESS(
        0 == setsockopt(*afd, SOL_TCP, TCP_KEEPCNT, &tcp_keepalive_cnt, sizeof(tcp_keepalive_cnt)),
        SocketMain_SocketSetOpt);
  }
  LOG(INFO) << "Sucessfully accepted connection on FD=" << *afd;
  return error::OK;
}

error::Error RunServerThread(core::Core* core, socketwrap::Socket* sock) {
  while (true) {
    context::Context ctx;
    auto in = ctx.Protobuf<socketmain::InboundMessage>();
    RETURN_IF_ERROR(sock->ReadPB(&ctx, in));
    if (in->inner_case() != socketmain::InboundMessage::kMsg) {
      return COUNTED_ERROR(SocketMain_InboundNotMessage);
    }
    auto msg = ctx.Protobuf<UntrustedMessage>();
    if (!msg->ParseFromString(in->mutable_msg()->data())) {
      return COUNTED_ERROR(SocketMain_InboundMessageParse);
    }
    auto status = core->Receive(&ctx, *msg);
    auto out = ctx.Protobuf<socketmain::OutboundMessage>();
    auto out_msg = out->mutable_msg();
    out_msg->set_id(in->msg().id());
    out_msg->set_status(status);
    RETURN_IF_ERROR(sock->WritePB(&ctx, *out));
  }
}

// Read an init message from a socket and use it to create a new core object.
std::pair<std::unique_ptr<core::Core>, error::Error> InitCore(socketwrap::Socket* sock) {
  context::Context ctx;
  auto pb = ctx.Protobuf<socketmain::InboundMessage>();
  LOG(INFO) << "Reading init message";
  if (error::Error err = sock->ReadPB(&ctx, pb); err != error::OK) {
    return std::make_pair(nullptr, err);
  }
  if (pb->inner_case() != socketmain::InboundMessage::kInit) {
    return std::make_pair(nullptr, COUNTED_ERROR(SocketMain_InboundNotInit));
  }
  auto init = pb->init();
  if (init.initial_log_level() != enclaveconfig::LOG_LEVEL_NONE) {
    util::SetLogLevel(init.initial_log_level());
  }
  env::Init(init.group_config().simulated());
  LOG(INFO) << "Creating core";
  auto [core_ptr, err] = core::Core::Create(
      &ctx,
      init);
  if (err == error::OK) {
    LOG(INFO) << "Writing init message";
    auto out = ctx.Protobuf<socketmain::OutboundMessage>();
    core_ptr->ID().ToString(out->mutable_init()->mutable_peer_id());
    err = sock->WritePB(&ctx, *out);
  }
  LOG(INFO) << "Core creation: " << err;
  return std::make_pair(std::move(core_ptr), err);
}

// Run a server, returning an error when it dies.
error::Error RunServer(int port, int sock_type) {
  int fd;
  RETURN_IF_ERROR(AcceptSocket(sock_type, port, &fd));
  socketwrap::Socket sock(fd);
  auto sockp = &sock;
  std::vector<std::thread> threads;
  threads.emplace_back([sockp]{
    LOG(INFO) << "Starting thread to send NSM messages";
    LOG(FATAL) << env::socket::SendSocketMessages(sockp);
  });
  auto [c, err] = InitCore(&sock);
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
  int port = 27427;
  int sock_type = 0;
  for (int i = 1; i < argc; i++) {
    std::string arg(argv[i]);
    if (arg.rfind("--port=", 0) == 0) {
      port = atoi(arg.data() + strlen("--port="));
      if (port > 0 && port < 65536) {
        LOG(INFO) << "Running on port " << port;
        continue;
      }
    } else if (arg == "--sock_type=af_inet") {
      LOG(INFO) << "Using socket type 'af_inet'";
      sock_type = AF_INET;
      continue;
    } else if (arg == "--sock_type=af_vsock") {
      LOG(INFO) << "Using socket type 'af_vsock'";
      sock_type = AF_VSOCK;
      continue;
    }
    LOG(FATAL) << "Usage: " << argv[0]
        << " --sock_type={af_inet,af_vsock} [--port=###]";
  }
  if (sock_type == 0) {
    LOG(FATAL) << "socket type not set, use --sock_type=xxx";
  }
  auto err = svr2::RunServer(port, sock_type);
  LOG(FATAL) << err;
  return -1;
}
