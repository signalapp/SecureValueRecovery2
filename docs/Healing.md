# Healing

When we talk about "healing" in SVR2, we're currently talking about membership
change in the Raft replica group.  In SVR2, we break healing down into
the following sub-problems:

- Remove old nodes when they're unable to serve (rebooted, etc)
- Add new nodes to replace removed nodes

Removing of nodes is currently unimplemented, more on that later.

## Adding new nodes

A new SVR2 node that wants to become a replica within the Raft cluster
currently goes through the following state transitions to get it to a
serving state.  These are currently driven by host-side requests, but
in near-future we hope to make the decision to promote replicas to
voting status an in-enclave decision.

In short, a node starts up without any Raft state.  It then decides
to follow one of two paths:

- Start a new Raft group as the sole replica/leader.
- Join an existing Raft group by talking to some replica in that group.

Starting a new Raft group is out of scope of this doc:  it just does :).
Joining an existing group, though, is the primary mechanism by which new
nodes are added.  We assume that we're running in an environment where
broken nodes are replaced (by shutting down the old node and starting up
a new one) as K8S and most other cloud provider workflows allow.  In this
case, "adding a new node" is actually "starting a new node, and having
it request to join the group".

Breaking this down in more detail, a node that wants to join a group
goes through a set of state transitions by talking to other nodes:

1. Host tells the enclave about a single peer ID
1. Get information about the Raft group (group ID, other replicas, etc)
1. Replicate existing state (logs/database) up to a recent commit
1. Send a `request_membership` request to the leader
1. Send a `request_vote` request to the leader

These steps are accomplished by calling enclave-to-enclave (e2e)
transactions (protos in `enclave/proto/e2e.proto`).

### Host join request

The host starts the join by sending a `HostToEnclaveRuequst.join_raft` call
to the enclave, with a PeerID it knows about that's part of the existing group.

### Get information about Raft group

The enclave calls the `e2e::TransactionRequest.get_raft` transaction on the one
peer ID it knows about (the one passed in by `join_raft`).  This gives it the
`RaftGroupConfig` (immutable Raft configuration) and `raft.ReplicaGroup`
(current membership in the group).  It then transitions to the next state.

### Replicate existing state

The enclave picks a random peer from among those in the `ReplicaGroup`
(it will eventually make a more interesting decision about which peer to talk
to), then makes a series of `e2e::TransactionRequest.replicate_state`
requests against that peer.  These requests first pull in all logs from
the remote peer until the new node reaches the responder's commit index.
At this point, the new node will start to request and receive a combination
of any new logs committed since that first commit point and database state.
When it's read in the full keyspace of the database (applying as it goes
any newly-committed logs it recieves), it will be at a point where it has
all logs and all database state up to the latest committed index of the
responder.  It then transitions to the next state.

### Request join

The enclave then requests to join the group as a non-voting member.
It sends an `e2e::TransactionRequest.request_raft_membership` to the
leader of the group (it actually sends it to all members, but should be
changed in the near future to target just the suspected leader).
If this request succeeds, it is now in a ReplicaGroup config on a
non-committed leader log.  The leader will begin to treat it as a normal
non-voting member initially, including replicating to it via AppendEntries
any uncommitted logs and telling it when those logs commits.  The node
stays in this state, watching its raft log, until it sees that a
ReplicaGroup log containing its PeerID has been committed.  At this point,
it knows that it is now a member, and transitions its local state to
act as such.

### Request vote

This is another mechanism that's currently driven by the host, but should
probably become an automatic enclave function.  After an enclave becomes
a non-voting member of the Raft group, the host can send a
`HostToEnclaveRuequst.request_voting` request to the enclave.  This
instructs the enclave to send an `e2e::TransactionRequest.request_raft_voting`
call to its current leader.  On success, the leader switches the replica's
voting status from non-voting to voting by writing a new ReplicaGroup with
the associated changes to its log.  The requesting node (and all other
nodes in the Raft group) hear about this change via normal mechanisms for
ReplicaGroup change.
