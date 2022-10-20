// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// This file contains all gauge metrics used within SVR2.
//
// They're created with the macro CREATE_GAUGE, which takes arguments:
//   * ns - namespace of the gauge (generally, module name)
//   * varname - name of the variable used to reference this gauge, must be
//     unique within the namespace (ns).  Also the exported name.
//
// Once these gauges are created here, they're used with the incantation:
//   GAUGE(ns, varname)->GaugeFunction();
// IE:
//   GAUGE(sender, enclave_messages_sent)->Set(12);
//
// Gauges are only exported after their first Set call, to avoid sending up
// spurious invalid values to metrics.  If Clear is called, they will no longer
// be exported.

CREATE_GAUGE(raft, role)
CREATE_GAUGE(raft, is_voting)
CREATE_GAUGE(raft, current_term)
CREATE_GAUGE(raft, commit_index)
CREATE_GAUGE(raft, promise_index)
CREATE_GAUGE(raft, log_oldest_stored_log_index)
CREATE_GAUGE(raft, log_last_log_term)
CREATE_GAUGE(raft, log_last_log_index)
CREATE_GAUGE(raft, log_size)
CREATE_GAUGE(raft, log_total_size)
CREATE_GAUGE(raft, log_entries)

CREATE_GAUGE(core, raft_state)
CREATE_GAUGE(core, last_index_applied_to_db)
CREATE_GAUGE(core, current_local_time)
CREATE_GAUGE(core, current_groupclock_time)


CREATE_GAUGE(peers, peers)

CREATE_GAUGE(client, clients)

CREATE_GAUGE(db, rows)

CREATE_GAUGE(timeout, timeouts)

CREATE_GAUGE(test, test1)
CREATE_GAUGE(test, test2)

CREATE_GAUGE(env, total_heap_size)
CREATE_GAUGE(env, allocated_heap_size)
CREATE_GAUGE(env, peak_heap_size)
