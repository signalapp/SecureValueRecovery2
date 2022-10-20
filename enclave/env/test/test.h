// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_ENV_TEST_TEST_H__
#define __SVR2_ENV_TEST_TEST_H__

#include <vector>
#include <string>
#include "proto/msgs.pb.h"

namespace svr2::env::test {

std::vector<EnclaveMessage> SentMessages();

}  // namespace svr2::env::test

#endif  // __SVR2_ENV_TEST_TEST_H__
