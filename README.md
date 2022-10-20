# Secure Value Recovery Service v2

The SecureValueRecovery2 (SVR2) project aims to store client-side secrets
server-side protected by a human-remembered (and thus, low-entropy) pin.
It does so by limiting the number of attempts to recover such a secret to
a very small guess count, to disallow brute-force attacks that would otherwise
trivially recover such a secret.  To limit the number of recovery attempts,
SVR2 keeps persistent state on the guess count, along with the secret itself,
in a multi-replica, strong-consensus, shared storage mechanism based on
in-memory Raft.

SVR2 is designed, first and foremost, to not leak the secret
material, and, secondarily, to provide the material back to clients.  Given
this, if there is a choice between "lose the secret material forever" and
"store the secret material but potentially leak it", we'll choose the former.
This means that, in some cases, we've chosen to allow the system to lose
_liveness_ (the ability to serve back anything) in order to maintain the
security properties of the system.  We'll happily discard every secret in the
system rather than expose one of the secrets to a leak.

## History

SVR2 is a successor to the
[SecureValueRecovery](https://github.com/signalapp/SecureValueRecovery)
project that Signal already uses for the above stated purpose.  We've built
a second version of this system to handle a few specific issues:

- Update to SGX DCAP capabilities
- Provide better operational handling of crashes/failures via self-healing
- Simplify to a single-replica-group model since SGX CPUs now have an EPC size of hundreds of gigabytes

As part of SGX DCAP updates, this project also attempts to be as safe as
possible while running on SGX TME memory, compared to the differing
security guarantees of the SGX MEE memory utilized in the original version.

## Building

In order to build and test everything in this repository, you should be able to
just run `make` at the top-level.  You must have a valid `docker` installed
locally to do this.  Running this at the top-level will:

- Create a docker image in which to build things
- Build `enclave/enclave.test` (a debug enclave for simulation/testing) and
  `enclave/enclave.signed` (a production enclave)
- Build and test the host-side process in `host/`

If you'd like to incrementally build and change things, you can do so by
running `make dockersh`.  This will build the aforementioned docker image,
then drop you inside of it in a `bash` shell.  You can then run any of

```
make all      # Make everything
make enclave  # Make all of the enclave stuf
make host     # Make all of the host stuff
(cd enclave && make $SOMETARGET)  # Make just a specific target in enclave
(cd host    && make $SOMETARGET)  # Make just a specific target in host
```

## Code layout

Code is divided into a few main directories at the top-level

*  `docker` - Contains the spec for the docker image used to build everything else.
*  `shared` - Contains all code/configs that must be shared between the host and enclave.
              This includes any protos that the host and enclave use to communicate,
              and the definitions of ocalls/ecalls (the `*.edl` files).
*  `enclave` - Contains all code and build rules for building the in-enclave binary.
               This is a C++ codebase.
*  `host` - Contains all code and build rules for building the host-side binary, which
            starts up an enclave, then communicates with it.  This is a Go codebase.
*  `docs` - Contains additional documentation above and beyond the host/enclave `README.md`
            docs on specific topics.

## License

Copyright 2023 Signal Messenger, LLC

Licensed under the [AGPLv3](LICENSE)
