// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RAFT_TYPES_H__
#define __SVR2_RAFT_TYPES_H__

#include <stdint.h>

namespace svr2::raft {

typedef uint64_t LogIdx;
typedef uint64_t TermId;
typedef uint64_t GroupId;

}  // namespace svr2::raft

#endif  // __SVR2_RAFT_TYPES_H__
