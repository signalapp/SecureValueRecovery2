// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_SENDER_SENDER_H__
#define __SVR2_SENDER_SENDER_H__

#include "proto/msgs.pb.h"
#include "proto/error.pb.h"

namespace svr2::sender {

// Send a message to the host.
void Send(const EnclaveMessage& msg);

}  // namespace svr2::sender

#endif  // __SVR2_SENDER_SENDER_H__
