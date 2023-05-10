# Enclave Messages: The Enclave's Logical Interface
The SVR2 enclave interface defined in [svr2.edl](../../shared/svr2.edl) is 
generic. It provides initialization and message passing functions that are
independent of the application logic. The _logical_ interface of the enclave
is defined by these messages and how the enclave responds to them. In what
follows we will think of the different messages that can be sent to the enclave
as RPCs and refer to them as "calls" or "commands".

## Three Interfaces: Host, Peer, and Client
SVR2 enclaves interact with three different types of entities: the _host_ that
makes ECALLs and receives OCALLs from the enclave, other _peer_ enclaves, and
_clients_ that are using the service to store and recover secure values.

The host interface includes a number of administrative commands (create or join
a replica group, get enclave status, tick the Raft timer, etc.). It also has 
commands to forward wrapped peer or client requests.

The peer interface includes Raft protocol messages, attestation updates, and
a number of other "Enclave to Enclave [E2E] transactions" used to get 
information about a replica group, transfer database state, and join a replica
group.

The client interface is the raison d'être for SVR2. It allows clients to backup,
restore, or delete a secure value. Everything else in this system is here to
ensure that this is done securely and reliably.

We will use this abstraction to organize this document, but it does *not* align
perfectly with the organization of the code. The code organization reflects
important implementation details as follows:

* All messages to the enclave are sent in an `UntrustedMessage`
  ([shared/proto/msgs.proto](../../shared/proto/msgs.proto)). These
  may be direct commands or forwarded messages from peers or clients.
* Host calls that will not trigger response messages are sent as a simple 
  `UntrustedMessage`.
  We will call these _synchronous host calls_.
* Host calls that MAY trigger response messages are sent as a
  `HostToEnclaveRequest` inside an `UntrustedMessage`. It is important to note
  that *all* client requests are sent this way.
* `HostToEnclaveRequest`s are further subdivided into administrative requests
  and requests on behalf of clients. Client requests may be Noise encrypted
  (backup, restore, delete) or unencrypted (create new client).
  Encrypted client messages are defined in 
  ([shared/proto/msgs.proto](../../shared/proto/msgs.proto)). Unencrypted ones
  are defined as submessages of `HostToEnclaveRequest` in
  ([shared/proto/msgs.proto](../../shared/proto/msgs.proto)).
* Peer calls are all sent as `PeerMessage` messages inside an
  `UntrustedMessage`. These messages contain raw bytes that either hold handshake
  information or a Noise encrypted `EnclaveToEnclaveMessage`. These messages
  are defined in [enclave/proto/e2e.proto](../proto/e2e.proto)

There is another important property that we will note on all of the calls we
describe: some calls require that a new Raft log entry be accepted and committed
by this node's replica group in order to complete, others do not. We will say that
the calls that succeed or fail based on whether a log entry was successfully
committed "require Raft consensus".

## The Host Interface

### Synchronous Calls
There are two messages the host can send to the enclave that act as
synchronous calls - once the ECALL returns the action is complete. No messages
will be sent from the enclave in response to these calls. None of these require Raft
consensus. They are:

1. `TimerTick` passes a unix timestamp that causes the enclave's to update its
   internal time (which is used to obtain a consensus `group_time` with its peers),
   then perform a `RaftStep`.
1. `ResetPeer` lets this Raft instance know that the given peer ID
    may have lost some of the messages we sent to it previously.

### Asynchronous Calls
All other calls from the host may cause the enclave to send response messages
that must be handled asynchronously. These are all sent as a
`HostToEnclaveRequest` inside an `UntrustedMessage`. These calls include:

1. **Reconfigure** (`enclaveconfig.EnclaveConfig`) Reconfigure the replica with 
   new host-supplied configuration.
1. **GetEnclaveStatus** (`bool`) Retrieves basic
   information about the status of a replica. Has more detail if the
   replica is a leader.
1. **DeleteBackup** (`DeleteBackupRequest` - _requires consensus_) Used by host
   to delete a backup, e.g., when the account is deleted.
1. **CreateNewRaftGroup** (`RaftConfig`) Request that we create a new raft group 
   from scratch, setting ourselves as the sole member and leader.  This should be
   done to seed a new Raft, after which we should requst `JoinRaft` instead.
1. **JoinRaft** (`JoinRaftRequest` - _requires consensus_) This tells the
   enclave to join a particular Replica group. This call requires that the 
   target raft group be up and running. Raft joining is a
   multi-step process described in detail in [Healing.md](./Healing.md). In
   this process there will be an enclave-to-enclave call that creates a new
   Raft configuration. This change requires consensus of the existing
   voting members. If successful the enclave will be a non-voting, 
   up-to-date member of the specified Raft.
1. **PingPeer** (`EnclavePeer`) Tells an enclave to check connectivity with 
   another peer.
1. **RequestVoting** (`bool` - _requires consensus_) Tells an enclave that
   is already a member of a replica group to request voting status. This
   requires a new Raft configuration to be accepted by a majority of the
   voting members of the *new* configuration.
1. **RequestMetrics** Get all metrics and gauges collected by the enclave.
1. **RefreshAttestation** Refresh attestations for peer and client connections.
1. **SetLogLevel** Sets the enclave's logging level with an `::svr2::EnclaveLogLevel`
   enum. These enum values match Open Enclave's [oe_log_level_t](https://github.com/openenclave/openenclave/blob/master/include/openenclave/log.h).
1. **RelinquishLeadership** (`bool` - _requires consensus_) If we are the Raft
   leader, give it up and attempt to pass leadership to an up-to-date peer without 
   waiting for the election timers.
1. **RequestRemoval** (`bool`- _requires consensus_) Request that this replica be removed from the Raft
   group.
1. **Hashes** (`bool`)Compute and return to the host a hash of the current DB.

## The Peer Interface
Peer to peer calls fall into three categories:
1. Raft messages
1. Connectivity messages
1. E2E Transactions

### Raft Messages
The Raft protocol messages defined in [enclave/raft.proto](../proto/raft.proto)
closely follow the Raft protocol defined in 
[Ongaro's thesis](https://web.stanford.edu/~ouster/cgi-bin/papers/OngaroPhD.pdf).

### Connectivity Messages
These messages are defined in [enclave/proto/e2e.proto](../proto/e2e.proto).
1. **Connect** (`e2e.ConnectRequest`) Sends attestation and handshake 
   information to initiate a connection with a peer. The response to this
   call contains attestation and handshake information for the called 
   enclave.
1. **AttestationUpdate** (`Attestation`) sends a new attestation to a peer so
   that peers can ensure their long-term connection with another enclave is
   still secure.

### Enclave to Enclave (E2E) Transactions

These messages are defined in [enclave/proto/e2e.proto](../proto/e2e.proto).

1. **GetRaft** (`e2e.GetRaftRequest`) Gets Raft membership information so that
   the enclave can initiate the joining process.
1. **ReplicateState** (`e2e.ReplicateStateRequest`) Requests a chunk of
   database state from a peer. This can include log messages and database rows.
1. **ReplicateStatePush** (`e2e.ReplicateStatePush`) 
1. **RaftMembershipRequest** (`bool` - _requires consensus_) Request
   to become a non-voting member of a replica group by setting this `true`.
   Assumes that the calling peer is loaded and up to date.
1. **RaftVotingRequest** (`bool` - _requires consensus_) Request
   to become a voting member of a replica group by setting this `true`.
   assumes that the calling peer is a non-voting member of the group.
1. **RaftWrite** (`bytes` - _requires consensus_) Forward a log entry to
   Raft leader to be added to the log.
1. **Ping** (`bool`) Request from a peer for simple acknowledgement to confirm 
   the connection to the requesting peer's host.
1. **NewTimestampUnixSecs** (`uint64`) Contains the sending peers timestamp. 
   Recipient will update peer and group times.
1. **RaftRemovalRequest** (`bool`) Creates a new replica group configuration without 
   the requesting peer in it, and submits this change to the new voting peers
   for committment.


## The Client Interface
The `client.*` messages are defined in 
[client.proto](../../shared/proto/client.proto). These are sent over the Noise
encrypted channel between the client and the enclave, wrapped in an
`ExistingClientRequest` submessage of a `HostToEnclaveRequest`.


1. **NewClient** (`NewClientRequest`) 
1. **CreateBackup** (`CreateBackupRequest` - _requires consensus_) Creates an
   empty backup row in the database.
1. **Backup** (`client.BackupRequest` - _requires consensus_) Stores a new value
   and resets the number of allowed tries for a given backup ID.
1. **RestoreBackup** (`client.RestoreRequest` - _requires consensus_) Presents an
   authorization token/PIN for a backup ID. If the token is correct, the secure
   value is retrieved from the database and sent to the client over the Noise 
   connection. If it is incorrect the number of allowed tries is decremented.
   If no more tries remain, the database row is deleted.
1. **DeleteBackup - client request** (`client.DeleteRequest` - _requires consensus_)
