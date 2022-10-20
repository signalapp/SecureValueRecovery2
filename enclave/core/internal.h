// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CORE_INTERNAL_H__
#define __SVR2_CORE_INTERNAL_H__

#include <mutex>

#include "raft/log.h"
#include "raft/raft.h"
#include "db/db.h"
#include "proto/e2e.pb.h"
#include "proto/msgs.pb.h"
#include "proto/raft.pb.h"

namespace svr2::core::internal {

typedef uint64_t TransactionID;

struct WaitingForFirstConnection {
  peerid::PeerID peer;
  TransactionID join_tx;
};
struct Loading {
  enclaveconfig::RaftGroupConfig group_config;
  raft::ReplicaGroup replica_group;
  std::unique_ptr<raft::Log> log;
  std::unique_ptr<db::DB> db;
  std::unique_ptr<raft::Membership> mem;
  peerid::PeerID load_from;
  TransactionID join_tx;
  bool started;
  uint64_t replication_id;
  uint64_t replication_sequence;
  std::string lexigraphically_largest_row_loaded_into_db;
};
struct Loaded {
  enclaveconfig::RaftGroupConfig group_config;
  std::unique_ptr<raft::Raft> raft;
  std::unique_ptr<db::DB> db;
  raft::LogIdx db_last_applied_log;
};
struct Raft {
  Raft() { ClearState(); }
  void ClearState() REQUIRES(mu) {
    state = svr2::RAFTSTATE_NO_STATE;
    waiting_for_first_connection = {
      .peer = peerid::PeerID(),
      .join_tx = 0,
    };
    loading = {
      .group_config = enclaveconfig::RaftGroupConfig(),
      .replica_group = raft::ReplicaGroup(),
      .log = nullptr,
      .db = nullptr,
      .join_tx = 0,
      .started = false,
      .replication_sequence = 0,
      .lexigraphically_largest_row_loaded_into_db = "",
    };
    loaded = {
      .group_config = enclaveconfig::RaftGroupConfig(),
      .raft = nullptr,
      .db = nullptr,
      .db_last_applied_log = 0,
    };
  }
  mutable util::mutex mu;  // protects everything else in this struct.
  RaftState state GUARDED_BY(mu);
  WaitingForFirstConnection waiting_for_first_connection GUARDED_BY(mu);
  Loading loading GUARDED_BY(mu);
  Loaded loaded GUARDED_BY(mu);
};

}  // namespace svr2::core::internal
#endif  // __SVR2_CORE_INTERNAL_H__
