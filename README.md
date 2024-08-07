# Secure Value Recovery Service v2/3

The SecureValueRecovery2 (SVR2) project aims to store client-side secrets
server-side protected by a human-remembered (and thus, low-entropy) pin.
It does so by limiting the number of attempts to recover such a secret to
a very small guess count, to disallow brute-force attacks that would otherwise
trivially recover such a secret.  To limit the number of recovery attempts,
SVR2 keeps persistent state on the guess count, along with the secret itself,
in a multi-replica, strong-consensus, shared storage mechanism based on
in-memory Raft.

The SVR3 project expands on this approach by implementing secret-sharing
across multiple hardware-protected backends (SGX, Nitro, SEV-SNP),
requiring breaking of all underlying hardware security models to extract
the necessary secrets.

SVR2/3 is designed, first and foremost, to not leak the secret
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

SVR3 builds upon the implemented SVR2 data model, exposing a different client
request/response protocol that exposes a Ristretto-based oblivious pseudo-
random function (OPRF) rather than a direct store/retrieve database.

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
*  `trustedimage` - Builds a trustable VM disk image based on the current enclave code,
                    for use in AMD SEV-SNP and other environments where the trusted unit is
                    a VM rather than a binary.

## Verifying build measurements

SVR2/3 clients can attest that a server is running a particular application version. These versions
are hard-coded into clients and correspond to artifacts published in this repository.
Depending on which trusted compute platform the server application is running on, you can
verify that the versioned artifact is built from the source code of this repository or at least
verify some details about what the remote software is running.

### Verifying SVR2 measurements
SVR2 only supports SGX. Clients attest that the server is running a particular enclave binary represented by an MRENCLAVE. SGX enclave builds deterministically reproducible. To verify, build the enclave binary from source yourself and checking the resulting MRENCLAVE value.

Suppose your client attests that the remote enclave has the MRENCLAVE [a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97](https://github.com/signalapp/Signal-Android/blob/4b8546a1510bbc6e54be5aeadd02aac2934ccee1/app/build.gradle.kts#L199)

```sh
# Checkout the commit that introduced the enclave
git checkout $(git log --diff-filter=A --pretty=format:"%h" -- enclave/releases/sgx/default.a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97) && git submodule update

# Enter the build environment
make dockersh

# Build the enclave
make enclave

# should match a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97
/opt/openenclave/bin/oesign dump -e enclave/build/enclave.signed | fgrep mrenclave
```

### Verifying SVR3 measurements
SVR3 supports multiple trusted compute platforms. The specifics of verification depend on the platform.
#### Verifying SGX measurements

See the SVR2 verification section. For SVR3, you can find what MRENCLAVE a client attests [in libsignal](https://github.com/signalapp/libsignal/blob/a4a0663528dadc38215e46c6f94484b435f5fe02/rust/attest/src/constants.rs#L21).
#### Verifying Nitro measurements

Nitro builds are also deterministic, and so you can verify an attested server corresponds to the committed source code by building the eif image yourself and comparing the resulting PCR measurements.

Suppose your client attests the nitro version [ffe631d7.52b91975.a4544fb5](https://github.com/signalapp/libsignal/blob/a4a0663528dadc38215e46c6f94484b435f5fe02/rust/attest/src/constants.rs#L21) with [these PCRs](https://github.com/signalapp/libsignal/blob/a4a0663528dadc38215e46c6f94484b435f5fe02/rust/attest/src/constants.rs#L29).

```sh
# Checkout the commit that introduced the nitro image
git checkout $(git log --diff-filter=A --pretty=format:"%h" -- enclave/releases/nitro/nitro.ffe631d7.52b91975.a4544fb5.eif) && git submodule update

# Enter the build environment
make dockersh

# Build the nitro images
make enclave_release

# you should have built `ffe631d7.52b91975.a4544fb5`
ls -lrth enclave/releases/nitro

# check the PCRs associated with the eif you built match the ones you attested
docker run -v "$(pwd)/enclave/releases/nitro:/enclaves" \
	--rm -it --entrypoint nitro-cli svr2_nsmeif  \
  describe-eif \
  --eif-path /enclaves/nitro.5582bdc0.52b91975.612eb43d.eif | grep PCR
```

### Verifying amd-sev-snp measurements

AMD-SEV-SNP platform attests an entire VM rather than a single binary or container. The VM images are not reproducibly built, so instead the entire image is committed to this repo. As a result, verification requires two steps:
1. Check that the committed image matches the attested measurements. If they match, you know that
the attested remote server is running the VM image committed to this repo.
2. Check that the committed image will run what you expect.

Releases are stored in `enclave/releases/gcpsnp/$RELEASE.tar.gz` and `enclave/releases/gcpsnp/$RELEASE.eventlog`.

#### Checking measurements
Suppose your client attests that the remote AMD-SEV-SNP image has the [PCR values]() associated with [version]()

We first must see what those measurements are.  That can be done by introspecting the `$RELEASE.eventlog`
file.

```sh
sudo apt-get install tpm2-tools yq
tpm2_eventlog enclave/releases/gcpsnp/$RELEASE.eventlog | yq .pcrs.sha256
```

The above command will output the SHA256 PCRs for the release.  These are the values that are
compiled into the Signal client (in libsignal) and can be checked against.  Some of these are ignored, so
only a subset will be visible within the Signal client.

#### Running the Verify Script

Run the following script to run numerous automated checks:

```
sudo apt-get install tpm2-tools yq
cd enclave/releases/gcpsnp
./verify_gcpsnp.sh $RELEASE
```

This script will unarchive the disk image for `$RELEASE`, mount the
root and boot partitions in an accessible location,  and run an initial set
of automated checks to make sure it matches the PCRs found in `$RELEASE.eventlog`.

If you have a prebuilt local image (created by running `make build/debian2.out`
in the trustedimage directory), it'll also compare files between the release
and that image, reporting which files differ.

It will then give you the option of keeping the partitions mounted so
that you can do any further investigation you see fit (checking against
known files, looking at systemd configuration, etc).

## License

Copyright 2023-2024 Signal Messenger, LLC

Licensed under the [AGPLv3](LICENSE)
