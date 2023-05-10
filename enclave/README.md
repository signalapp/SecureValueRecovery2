# SVR2 Enclave Code

SVR2 uses C++ as its language for building an in-enclave binary. The details
of the build process and the host-enclave interaction depend on the platform.
Since SVR2 is deployed on Intel SGX, this document will describe SGX-specific
implementation details. 

For SGX, the enclave binary is built with the OpenEnclave (hereafter 'OE') 
SDK.  The binary, `enclave.bin` is then signed via OE's `oesign`, which 
doesn't matter to us because we don't trust the signature,
just the unique ID (SGX "mrenclave") of the resulting signed config.  However,
the `oesign` process does one important thing:  it binds a config (either
`svr2_test.conf` or `svr2.conf` to the resulting object.  Once this process
is complete, the resulting `enclave.signed` file is ready to be loaded into a
DCAP-based SGX enclave.

# Host/enclave communication

After initialization, all host/enclave communication happens through a single 
ocall/ecall combination, defined in `../shared/svr2.edl`:

- `svr2_input_message`:  Enclave receives a message (a serialized
  `HostToEnclaveMessage` protobuf) from the host.
- `svr2_output_message`:  Enclave sends a message (a serialized
  `EnclaveToHostMessage` protobuf) to the host.

Certain messages are 'transactions', or messages with a `Request` that want
a specific `Reply`.  It is important to note that if a request is
passed in via a message, the response associated with it may not be part of
the returned list.  IE: the host may pass in a transaction request, above,
via `EnclaveToHostMessage1`, but may not get back the reply until
`HostToEnclaveMessage4.1`.  Transactions have associated transaction IDs,
which allow for disambiguating requests and their associated responses.
Hosts may send transactions to enclaves and enclaves to hosts.  Each direction
maintains a unique keyspace for transaction IDs (so HostToEnclave transaction 1
and EnclaveToHost transaction 1 are distinct), and each is responsible for
making sure that transaction requests that they pass are uniquely identified.

## Code Layout

Code is broken into a set of modules, where each module is a one-level-deep
subdirectory within the top-level `enclave` directory.  Each module is
independently compiled, then all modules are combined in a final linking step
to form the resulting binary.  Modules are listed as `LIBRARIES` within
`Makefile`, and must form a DAG of dependencies.  Within the `LIBRARIES` list,
higher libraries may depend on lower libraries, but not vice versa.

Code roughly follows the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).

# Concurrency in SVR2 Enclave

With SVR2, we're aiming to utilize a single replica group to serve all traffic.
This, of course, brings up issues around scalability.  We can of course add
new replicas to the replica group, but with a strong consensus model relying
on agreement between a quorum (in our case, a simple majority) of voting
replicas, additional replicas have the potential to add load rather than shed
it.

To handle this, SVR2 is built to, as much as possible, utilize the resources
of non-leader and non-voting replicas.  While we're unable to shed or reduce
load on RAM with added members (each replica needs to store the entire
database), we can shed load in the form of CPU and network resources.

## Utilizing multiple cores

Even without considering excess replicas, we aim to utilize the resources
of each replica to the fullest extent.  To do this, the SVR2 enclave binary
is built as a true multi-threaded process, with targetted locking of code
subsections allowing parallel processing as much as possible.

One of the most CPU-intensive tasks that SVR2 partakes in is encryption
and decryption.  This takes place when replicas communicate with each
other ("peer communication") and when they accept and service connections
from clients ("client communication").  When establishing these secure
connections, the initial handshake is more CPU-intensive, followed
by less intensive block cipher encryption/decryption.  Peer communication
uses long-lived sessions that amortize handshake cost over a long period
of time, while client communication requires a new handshake, a small
amount of communication, and a subsequent closing of the connection.

For both peer and client communication, we aim to be highly parallel on
a single machine:  handshaking and block-cipher encryption/decryption
are done with client- and peer-level locks, rather than global ones.
This approach, though, lays some requirements on the host side, as
for both cases, reordering of messages breaks the block-cipher
assumptions of the clients/peers.  Internally, SVR2 maintains correct
order of messages it outputs to peers and clients:  if message A
to a peer or client happens before message B, then `svr2_output_message(A)`
will be called and allowed to complete before `svr2_output_message(B)`.
However, on the host side, care must be taken to respect this
ordering: when messages are forwarded externally or received from external
hosts, their calls to `svr2_input_message` should follow the same pattern:
if A is received before B in either a peer or client stream, then
`svr2_input_message(A)` should be called and allowed to complete before
`svr2_input_message(B)` is called.

Some global locks are of course still required, in particular around Raft
and its associated logs/database.  However, these locked sections are kept
at a minimimum, with as much work done as possible before/after the locks
are acquired.

## Utilizing multiple machines

The primary means to scale SVR2 is the addition of replicas.  However,
as mentioned, this has the potential to hinder scaling, especially if
the leader alone is allowed to perform CPU-intensive tasks like servicing
client requests.  For this reason, SVR2 is built to allow any replica to
service requests from any client.

When a client connects to SVR2 in a non-leader replica, it will perform
the client handshake and receive/decrypt the client's request entirely
on its own.  Once it has done so, it will forward the request to the current
leader as an enclave-to-enclave transaction, receiving in response either
a failure or a log location (an `(index, term)` pair) associated with the
write.  Failures are immediately returned to the client.  A success, though,
creates a watch-point in the non-leader replica's raft log at `index`.
The replica will wait until `index` is a committed part of its own log (via
normal Raft `AppendEntries` mechanisms), then will check the `term` of the
committed log.  If that matches the `term` returned from its write request,
by definition the log at `index` contains the client's request, and when
applying that request to its local database, it can safely return the
response to that client over its still-open channel.

By this mechanism, load (especially client handshake and communication
load) can be shared across all replicas.  Crucially, this includes
non-voting replicas, which can be added with minimal increase to the
load on the voting replicas.  As non-voting replicas still receive
Raft logs and their commitments, they can happily service client
requests.

## More topics
-  [Raft healing](../docs/Healing.md)
-  [Enclave messages](../docs/Messages.md)
