// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_NSM_NSM_H__
#define __SVR2_ENV_NSM_NSM_H__

#include "socketwrap/socket.h"
#include "proto/error.pb.h"

namespace svr2::env::nsm {

// Send all outstanding messages, in order, up to the host.
error::Error SendNsmMessages(socketwrap::Socket* sock);

}  // namespace svr2::env::nsm

#endif  // __SVR2_ENV_NSM_NSM_H__
