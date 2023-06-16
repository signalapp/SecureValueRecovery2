// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// This file contains all counter metrics used within SVR2.
//
// They're created with the macro CREATE_COUNTER, which takes arguments:
//   * ns - namespace of the counter (generally, module name)
//   * varname - name of the variable used to reference this counter, must be
//     unique within the namespace (ns)
//   * name - name of the exported variable (actually, "ns.name")
//   * tags - set of tags associated with this variable, either empty `({})`, or
//     an initializer list `({{"foo", "bar"}, {"baz", "blah"}})` for tags
//     foo=bar, baz=blah.  Must be wrapped in parens.
//
// Once these counters are created here, they're used with the incantation:
//   COUNTER(ns, varname)->CounterFunction();
// IE:
//   COUNTER(sender, enclave_messages_sent)->IncrementBy(3);
//
// All counters created here will be exported to the host, even if they are
// zero.  This differs from error counts, which are exported only if non-zero.

CREATE_COUNTER(ecalls, host_messages_received, host_messages_received, ({}))
CREATE_COUNTER(ecalls, host_bytes_received, host_bytes_received, ({}))
CREATE_COUNTER(ecalls, init_calls, init_calls, ({}))

CREATE_COUNTER(sender, enclave_messages_sent, enclave_messages_sent, ({}))
CREATE_COUNTER(sender, enclave_bytes_sent, enclave_bytes_sent, ({}))

CREATE_COUNTER(core, host_requests_received, msgs_received, ({{"type", "host_request"}}))
CREATE_COUNTER(core, peer_msgs_received,     msgs_received, ({{"type", "peer_message"}}))
CREATE_COUNTER(core, timer_ticks_received,   msgs_received, ({{"type", "timer_tick"}}))
CREATE_COUNTER(core, invalid_msgs_received,  msgs_received, ({{"type", "invalid"}}))
CREATE_COUNTER(core, new_client_success, new_clients, ({{"outcome", "success"}}))
CREATE_COUNTER(core, new_client_failure, new_clients, ({{"outcome", "failure"}}))
CREATE_COUNTER(core, log_transactions_success, log_transactions, ({{"outcome", "success"}}))
CREATE_COUNTER(core, log_transactions_cancelled, log_transactions, ({{"outcome", "cancelled"}}))
CREATE_COUNTER(core, host_delete_success, host_delete, ({{"outcome", "success"}}))
CREATE_COUNTER(core, host_delete_failure, host_delete, ({{"outcome", "failure"}}))
CREATE_COUNTER(core, client_transaction_success, client_transaction, ({{"outcome", "success"}}))
CREATE_COUNTER(core, client_transaction_cancelled, client_transaction, ({{"outcome", "cancelled"}}))
CREATE_COUNTER(core, client_transaction_error, client_transaction, ({{"outcome", "error"}}))
CREATE_COUNTER(core, client_transaction_invalid, client_transaction, ({{"outcome", "invalid"}}))
CREATE_COUNTER(core, client_transaction_dne, client_transaction, ({{"outcome", "dne"}}))
CREATE_COUNTER(core, client_transaction_encrypterr, client_transaction, ({{"outcome", "encrypterr"}}))
CREATE_COUNTER(core, raft_log_applied, raft_log_applied, ({}))

CREATE_COUNTER(client, created, created, ({}))
CREATE_COUNTER(client, closed, closed, ({}))
CREATE_COUNTER(client, new_dh_state, new_dh_state, ({}))
CREATE_COUNTER(client, key_rotate_success, key_rotate, ({{"outcome", "success"}}))
CREATE_COUNTER(client, key_rotate_failure, key_rotate, ({{"outcome", "failure"}}))
CREATE_COUNTER(client, attestation_refresh_success, attestation_refresh, ({{"outcome", "success"}}))
CREATE_COUNTER(client, attestation_refresh_failure, attestation_refresh, ({{"outcome", "failure"}}))

CREATE_COUNTER(peers, attestation_refresh_success, attestation_refresh, ({{"outcome", "success"}}))
CREATE_COUNTER(peers, attestation_refresh_failure, attestation_refresh, ({{"outcome", "failure"}}))

CREATE_COUNTER(raft, logs_committed, logs_committed, ({}))
CREATE_COUNTER(raft, logs_promised, logs_promised, ({}))
CREATE_COUNTER(raft, vote_requests_received, msgs_received, ({{"type", "vote_request"}}))
CREATE_COUNTER(raft, vote_responses_received, msgs_received, ({{"type", "vote_response"}}))
CREATE_COUNTER(raft, append_requests_received, msgs_received, ({{"type", "append_request"}}))
CREATE_COUNTER(raft, append_responses_received, msgs_received, ({{"type", "append_response"}}))
CREATE_COUNTER(raft, timeout_nows_received, msgs_received, ({{"type", "timeout_now"}}))
CREATE_COUNTER(raft, invalid_requests_received, msgs_received, ({{"type", "invalid"}}))
CREATE_COUNTER(raft, term_updated, term_updated, ({}))
CREATE_COUNTER(raft, term_increments, term_increments, ({}))
CREATE_COUNTER(raft, logs_append_success, logs_appended, ({{"outcome", "success"}}))
CREATE_COUNTER(raft, logs_append_failure, logs_appended, ({{"outcome", "failure"}}))
CREATE_COUNTER(raft, election_timeouts, election_timeouts, ({}))

CREATE_COUNTER(timeout, timeouts_created, timeouts_created, ({}))
CREATE_COUNTER(timeout, timeouts_run, timeouts_completed, ({{"outcome", "run"}}))
CREATE_COUNTER(timeout, timeouts_cancelled, timeouts_completed, ({{"outcome", "cancelled"}}))

CREATE_COUNTER(context, cpu_uncategorized, cpu, ({{"in", "uncategorized"}, {"action", "uncategorized"}}))
CREATE_COUNTER(context, cpu_client_encrypt, cpu, ({{"in", "client"}, {"action", "encrypt"}}))
CREATE_COUNTER(context, cpu_client_decrypt, cpu, ({{"in", "client"}, {"action", "decrypt"}}))
CREATE_COUNTER(context, cpu_client_hs_start, cpu, ({{"in", "client"}, {"action", "hs_start"}}))
CREATE_COUNTER(context, cpu_client_hs_finish, cpu, ({{"in", "client"}, {"action", "hs_finish"}}))
CREATE_COUNTER(context, cpu_peer_encrypt, cpu, ({{"in", "peer"}, {"action", "encrypt"}}))
CREATE_COUNTER(context, cpu_peer_decrypt, cpu, ({{"in", "peer"}, {"action", "decrypt"}}))
CREATE_COUNTER(context, cpu_peer_connect, cpu, ({{"in", "peer"}, {"action", "connect"}}))
CREATE_COUNTER(context, cpu_peer_connect2, cpu, ({{"in", "peer"}, {"action", "connect2"}}))
CREATE_COUNTER(context, cpu_peer_accept, cpu, ({{"in", "peer"}, {"action", "accept"}}))
CREATE_COUNTER(context, cpu_db_client_request, cpu, ({{"in", "db"}, {"action", "client_request"}}))
CREATE_COUNTER(context, cpu_db_repl_send, cpu, ({{"in", "db"}, {"action", "repl_send"}}))
CREATE_COUNTER(context, cpu_db_repl_recv, cpu, ({{"in", "db"}, {"action", "repl_recv"}}))
CREATE_COUNTER(context, cpu_db_hash, cpu, ({{"in", "db"}, {"action", "hash"}}))
CREATE_COUNTER(context, cpu_core_client_msg, cpu, ({{"in", "core"}, {"action", "client_msg"}}))
CREATE_COUNTER(context, cpu_core_peer_msg, cpu, ({{"in", "core"}, {"action", "peer_msg"}}))
CREATE_COUNTER(context, cpu_core_host_msg, cpu, ({{"in", "core"}, {"action", "host_msg"}}))
CREATE_COUNTER(context, cpu_core_raft_msg, cpu, ({{"in", "core"}, {"action", "raft_msg"}}))
CREATE_COUNTER(context, cpu_core_e2e_txn_req, cpu, ({{"in", "core"}, {"action", "e2e_txn_req"}}))
CREATE_COUNTER(context, cpu_core_e2e_txn_resp, cpu, ({{"in", "core"}, {"action", "e2e_txn_resp"}}))
CREATE_COUNTER(context, cpu_core_repl_send, cpu, ({{"in", "core"}, {"action", "repl_send"}}))
CREATE_COUNTER(context, cpu_core_repl_recv, cpu, ({{"in", "core"}, {"action", "repl_recv"}}))
CREATE_COUNTER(context, cpu_core_committed_logs, cpu, ({{"in", "core"}, {"action", "committed_logs"}}))
CREATE_COUNTER(context, cpu_core_timer_tick, cpu, ({{"in", "core"}, {"action", "timer_tick"}}))
CREATE_COUNTER(context, cpu_core_host_database_req, cpu, ({{"in", "core"}, {"action", "host_db_req"}}))
CREATE_COUNTER(context, cpu_core_metrics, cpu, ({{"in", "core"}, {"action", "metrics"}}))
CREATE_COUNTER(context, cpu_test_database_entries, cpu, ({{"in", "core"}, {"action", "test_database_entries"}}))
CREATE_COUNTER(context, lock_core_raft, cpu, ({{"in", "core"}, {"action", "lock"}, {"lock", "core_raft"}}))
CREATE_COUNTER(context, lock_core_log_txns, cpu, ({{"in", "core"}, {"action", "lock"}, {"lock", "core_log_txns"}}))
CREATE_COUNTER(context, lock_core_e2e_txns, cpu, ({{"in", "core"}, {"action", "lock"}, {"lock", "core_e2e_txns"}}))
CREATE_COUNTER(context, lock_core_config, cpu, ({{"in", "core"}, {"action", "lock"}, {"lock", "core_config"}}))
CREATE_COUNTER(context, lock_groupclock, cpu, ({{"in", "groupclock"}, {"action", "lock"}, {"lock", "groupclock"}}))
CREATE_COUNTER(context, lock_timeout, cpu, ({{"in", "timeout"}, {"action", "lock"}, {"lock", "timeout"}}))
CREATE_COUNTER(context, lock_peermanager, cpu, ({{"in", "peer"}, {"action", "lock"}, {"lock", "peermanager"}}))
CREATE_COUNTER(context, lock_peer, cpu, ({{"in", "peer"}, {"action", "lock"}, {"lock", "peer"}}))
CREATE_COUNTER(context, lock_clientmanager, cpu, ({{"in", "client"}, {"action", "lock"}, {"lock", "clientmanager"}}))
CREATE_COUNTER(context, lock_client, cpu, ({{"in", "client"}, {"action", "lock"}, {"lock", "client"}}))
CREATE_COUNTER(context, lock_test, cpu, ({{"in", "test"}}))
CREATE_COUNTER(context, lock_socket_read, socket, ({{"in", "socket"}, {"action", "lock"}, {"lock", "read"}}))
CREATE_COUNTER(context, lock_socket_write, socket, ({{"in", "socket"}, {"action", "lock"}, {"lock", "write"}}))
