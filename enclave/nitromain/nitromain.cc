// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

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

#define RETURN_ERRNO_ERROR_IF(x, err) do { \
  if ((x)) { \
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
error::Error AcceptSocket(int* afd) {
  int fd;
  RETURN_ERRNO_ERROR_IF(
      0 >= (fd = socket(AF_VSOCK, SOCK_STREAM, 0)),
      Nitro_SocketCreation);

  struct sockaddr_vm my_addr;
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.svm_family = AF_VSOCK;
  my_addr.svm_port = VMADDR_PORT_ANY;
  my_addr.svm_cid = VMADDR_CID_ANY;
  RETURN_ERRNO_ERROR_IF(
      0 != bind(fd, (struct sockaddr *) &my_addr, sizeof(my_addr)),
      Nitro_SocketBind);
  RETURN_ERRNO_ERROR_IF(
      0 != listen(fd, 2),
      Nitro_SocketListen);

  *afd = 0;
  while (*afd <= 0) {
    struct sockaddr_vm remote_addr;
    socklen_t remote_len = sizeof(remote_addr);
    *afd = accept4(fd, reinterpret_cast<struct sockaddr*>(&remote_addr), &remote_len, SOCK_CLOEXEC);
    RETURN_ERRNO_ERROR_IF(
        *afd <= 0 && errno != EINTR && errno != ECONNABORTED,
        Nitro_SocketAccept);
  }
  shutdown(fd, SHUT_RDWR);
  close(fd);
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
std::pair<std::unique_ptr<core::Core>, error::Error> InitCore(socketwrap::Socket* sock) {
  context::Context ctx;
  auto init = ctx.Protobuf<nitro::InboundMessage>();
  if (error::Error err = sock->ReadPB(&ctx, init); err != error::OK) {
    return std::make_pair(nullptr, err);
  }
  if (init->inner_case() != nitro::InboundMessage::kInit) {
    return std::make_pair(nullptr, COUNTED_ERROR(Nitro_InboundNotInit));
  }
  auto [core_ptr, err] = core::Core::Create(
      &ctx,
      init->init());
  if (err == error::OK) {
    auto out = ctx.Protobuf<nitro::OutboundMessage>();
    core_ptr->ID().ToString(out->mutable_init()->mutable_peer_id());
    err = sock->WritePB(&ctx, *out);
  }
  return std::make_pair(std::move(core_ptr), err);
}

// Run a server, returning an error when it dies.
error::Error RunServer() {
  int fd;
  RETURN_IF_ERROR(AcceptSocket(&fd));
  socketwrap::Socket sock(fd);
  auto sockp = &sock;
  std::vector<std::thread> threads;
  threads.emplace_back([sockp]{
    LOG(FATAL) << env::nsm::SendNsmMessages(sockp);
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

error::Error Run() {
  env::Init();
  return RunServer();
}

}  // namespace svr2

int main(int argc, char** argv) {
  LOG(FATAL) << svr2::Run();
  return -1;
}
