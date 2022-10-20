// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "sender/sender.h"
#include "env/env.h"
#include "metrics/metrics.h"

namespace svr2::sender {

// Send a message to the host.
void Send(const EnclaveMessage& msg) {
  std::string serialized;
  CHECK(msg.SerializeToString(&serialized));
  CHECK(error::OK == env::environment->SendMessage(serialized));
  COUNTER(sender, enclave_messages_sent)->Increment();
  COUNTER(sender, enclave_bytes_sent)->IncrementBy(serialized.size());
}

}  // namespace svr2::sender
