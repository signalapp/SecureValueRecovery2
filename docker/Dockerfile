# syntax=docker/dockerfile:1
# To build use:
# docker build -t oebuild .
FROM amd64/debian:buster@sha256:2a0c1b9175adf759420fe0fbd7f5b449038319171eb76554bb76cbe172b62b42 AS base

LABEL description="linux build environment for sgx."

COPY docker/apt.conf docker/sources.list /etc/apt/
RUN while true; do apt update && break; done && \
    while true; do apt install -y \
      gpg \
      gnupg2 \
      wget \
      software-properties-common \
    && break; done
    

COPY docker/sgx.sources.list docker/ms.sources.list /etc/apt/sources.list.d/
# ms and intel repos keep old packages around,
# however if they remove some of these in the future
# binary packages can be retrieved from github releases
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    while true; do apt update && break; done && \
    while true; do apt install -y \
    libsgx-ae-id-enclave=1.22.100.3-focal1 \
    libsgx-ae-pce=2.25.100.3-focal1 \
    libsgx-ae-qe3=1.22.100.3-focal1 \
    libsgx-dcap-ql=1.22.100.3-focal1 \
    libsgx-dcap-ql-dev=1.22.100.3-focal1 \
    libsgx-enclave-common=2.25.100.3-focal1 \
    libsgx-headers=2.25.100.3-focal1 \
    libsgx-pce-logic=1.22.100.3-focal1 \
    libsgx-qe3-logic=1.22.100.3-focal1 \
    libsgx-urts=2.25.100.3-focal1 \
    && break; done
ARG OPENENCLAVE_VERSION=0.19.10
ARG OPENENCLAVE_HASH=5262223d6bc01ddc2e503fb26a26b851841a2b410228109b9f388984fc328c5a
ADD --checksum=sha256:${OPENENCLAVE_HASH} \
    https://github.com/openenclave/openenclave/releases/download/v${OPENENCLAVE_VERSION}/Ubuntu_2004_open-enclave_${OPENENCLAVE_VERSION}_amd64.deb ./
RUN dpkg -i Ubuntu_2004_open-enclave_${OPENENCLAVE_VERSION}_amd64.deb

FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240611.0@sha256:e96baa46e2effb0f69d488007bde35a7d01d7fc2ec9f4e1cd65c59846c01775e AS nsmbuild
ENV HOST_MACHINE=x86_64
ENV RUST_VERSION=1.58.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN yum install -y gcc

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs/ | sh -s -- --default-toolchain ${RUST_VERSION} -y ; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version

COPY docker/aws-nitro-enclaves-nsm-api /build
COPY docker/aws-nitro.Cargo.lock /build/Cargo.lock
WORKDIR /build 

RUN set -eux; \
    (cd nsm-lib && cargo build --release --locked)
RUN ar mD target/release/libnsm.a $(ar t target/release/libnsm.a | env -u LANG LC_ALL=C sort)

FROM base AS builder

RUN mkdir /src && \
    while true; do apt update && break; done && \
    while true; do apt install -y \
      clang-11 \
      libssl-dev \
      gdb \
      libtool \
      bison \
      automake \
      flex \
      libcurl4 \
      pkg-config \
      make \
      unzip \
      git \
      gcc \
      libgtest-dev \
      cmake \
      valgrind \
    && break; done

ARG PROTOBUF_PLATFORM=linux-x86_64
ARG PROTOBUF_VERSION=21.8
ARG PROTOBUF_BASE=protoc-${PROTOBUF_VERSION}-${PROTOBUF_PLATFORM}

ADD --checksum=sha256:f90d0dd59065fef94374745627336d622702b67f0319f96cee894d41a974d47a https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOBUF_BASE}.zip ./
RUN mkdir -p ${PROTOBUF_BASE} \
	&& cd ${PROTOBUF_BASE} \
  && unzip -o ../${PROTOBUF_BASE}.zip \
  && cd .. \
  && mv ${PROTOBUF_BASE} /opt/protobuf

ARG GOLANG_PLATFORM=linux-amd64
ARG GOLANG_VERSION=1.21.3
ARG GOLANG_TAR_GZ=go${GOLANG_VERSION}.${GOLANG_PLATFORM}.tar.gz

ADD --checksum=sha256:1241381b2843fae5a9707eec1f8fb2ef94d827990582c7c7c32f5bdfbfd420c8 https://go.dev/dl/${GOLANG_TAR_GZ} ./
RUN tar xzf ${GOLANG_TAR_GZ} \
  && mv go /opt/

ENV PATH="/opt/openenclave/bin:/opt/go/bin:/opt/protobuf/bin:${PATH}"
ENV GOROOT="/opt/go"
ENV GOBIN="/opt/go/bin"
ENV PKG_CONFIG_PATH="/opt/openenclave/share/pkgconfig"

ARG PROTOC_GEN_GO_GITREV=6875c3d7242d1a3db910ce8a504f124cb840c23a
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_GITREV}
RUN echo "export PS1='buildenv: \w$ '" >> /etc/bash.bashrc

# Set this after `go install` so we don't use the same cache as root.
ENV GOPATH="/src/.gopath"
ENV GOCACHE="/src/.gocache"
ENV CARGO_HOME="/src/.cargohome"
ENV CARGO_TARGET_DIR="/src/.cargotarget"

WORKDIR /src
COPY --from=nsmbuild /build/target/release/libnsm.a /opt/nsm/libnsm.a
COPY --from=nsmbuild /build/target/release/nsm.h    /opt/nsm/nsm.h

ADD --checksum=sha256:ce552d6bf22a2544ea78647d98cb405d5089af58dbcaa4efea711bf8becd71c5 https://static.rust-lang.org/dist/rust-1.79.0-x86_64-unknown-linux-gnu.tar.xz /tmp/
RUN apt-get install -y xz-utils && \
    (cd /tmp && tar xJf /tmp/rust-1.79.0-x86_64-unknown-linux-gnu.tar.xz) && \
    (cd /tmp/rust-1.79.0-x86_64-unknown-linux-gnu && ./install.sh)

CMD ["/bin/bash"]

FROM base AS sgxrun

RUN apt-get update && apt-get install -y \
    libsgx-dcap-default-qpl=1.22.100.3-focal1 \
    libsgx-dcap-default-qpl-dev=1.22.100.3-focal1 \
    libcurl4
COPY host/main /bin/svr2
COPY enclave/releases/sgx /enclaves
COPY host/cmd/control/control /bin/svr3control
RUN ln -s /bin/svr3control /bin/svr2control

ENTRYPOINT ["/bin/svr2"]

FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240611.0@sha256:e96baa46e2effb0f69d488007bde35a7d01d7fc2ec9f4e1cd65c59846c01775e AS nsmrun
ADD --chown=0:0 enclave/build/enclave.nsm /bin/svr2
ENTRYPOINT ["/bin/svr2", "--sock_type=af_vsock"]

FROM alpine@sha256:ff6bdca1701f3a8a67e328815ff2346b0e4067d32ec36b7992c1fdc001dc8517 AS sevrun
COPY enclave/build/enclave.sev /bin/svr2
EXPOSE 27427
ENTRYPOINT ["/bin/svr2", "--sock_type=af_inet"]

FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240611.0@sha256:e96baa46e2effb0f69d488007bde35a7d01d7fc2ec9f4e1cd65c59846c01775e AS nsmeif
RUN yum install -y \
    aws-nitro-enclaves-cli.x86_64 \
    aws-nitro-enclaves-cli-devel.x86_64 \
    perl \
    docker \
    jq
ENV DOCKER_IMAGE svr2_nsmrun:latest
ENV OUTPUT_FILE /tmp/svr2.eif
ENV CHOWN_TO 0:0
COPY docker/build_eif.sh build_eif.sh
ENTRYPOINT ./build_eif.sh

FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:e96baa46e2effb0f69d488007bde35a7d01d7fc2ec9f4e1cd65c59846c01775e AS nsmhost
RUN yum install -y \
    aws-nitro-enclaves-cli.x86_64 \
    jq
ADD --checksum=sha256:cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8 https://www.openssl.org/source/openssl-1.1.1w.tar.gz /tmp/
RUN set -x && \
    cd /tmp && \
    yum install -y perl tar && \
    tar xvzf openssl-1.1.1w.tar.gz && \
    cd openssl-1.1.1w && \
    ./config && \
    make -j16 >/dev/null && \
    make install -j16 >/dev/null && \
    echo /usr/local/lib64 | tee /etc/ld.so.conf.d/openssl.conf && \
    ldconfig && \
    yum remove -y perl tar && \
    rm -rf /tmp/openssl*
COPY docker/nitro_start.sh nitro_start.sh
RUN mkdir /releases
COPY enclave/releases/nitro/* /releases
COPY host/main /bin/svr2
COPY host/cmd/control/control /bin/svr3control
RUN ln -s /bin/svr3control /bin/svr2control
ENTRYPOINT ["./nitro_start.sh"]
