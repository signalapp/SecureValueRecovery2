# Healing

When we talk about "healing" in SVR2, we're currently talking about membership
change in the Raft replica group.  In SVR2, we break healing down into
the following sub-problems:

- Remove old nodes when they're unable to serve (rebooted, etc)
- Add new nodes to replace removed nodes

## Removing Nodes
An SVR2 node that fails or otherwise becomes disconnected from its replica
group will eventually be removed from the group without intervention. This is
a two step process. First, if the leader has not received a message from a follower for
`replica_voting_timeout_ticks` ticks (configured in the `RaftConfig`), it will 
propose a membership change to the group that demotes this replica to non-voting
status. If a total of `replica_membership_timeout_ticks` ticks elapses without
receiving a message from a replica, then the leader will propose a membership change
to the group that removes this replica. When these changes happen, if other non-voting
replicas are available and needed, the leader will propose to promote them to voting
status.

This process works for unexpected interruptions but is slow. When an SVR2 node needs
to be shut down quickly in a controlled manner this can be done by sending a
`relinquish_leadership` command (if the node is a leader), then a `request_removal`
command. This process happens automatically when the host gets a SIGTERM.

## Adding new nodes

A new SVR2 node that wants to become a replica within the Raft cluster
currently goes through the following state transitions to get it to a
serving state.  These are currently driven by host-side requests, but
the decision to promote replicas to voting status is also made in-enclave
when loaded non-voting replicas are available and more voting members are
allowed.

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

The host starts the join by sending a `HostToEnclaveRequest.join_raft` call
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

This is another mechanism that can driven by the host, but is also handled
automatically by the enclave in some situations.  After an enclave becomes
a non-voting member of the Raft group, the host can send a
`HostToEnclaveRequest.request_voting` request to the enclave.  This
instructs the enclave to send an `e2e::TransactionRequest.request_raft_voting`
call to its current leader.  On success, the leader switches the replica's
voting status from non-voting to voting by writing a new ReplicaGroup with
the associated changes to its log.  The requesting node (and all other
nodes in the Raft group) hears about this change via normal mechanisms for
ReplicaGroup change.

It is possible to configure an SVR2 replica group without using host-driven
calls to request voting. As long as the number of voting members in a group
is less than the `max_voting_replicas` value in the `RaftConfig` for the group,
the leader will promote the most recently seen non-voting member of the group.
This means that if an administrator adds `max_voting_replicas-1` members to a 
group using the `request_raft_membership` command, they will all eventually 
become voting members without further commands from the host.
