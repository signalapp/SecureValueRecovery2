# syntax=docker/dockerfile:1
# To build use:
# docker build -t oebuild .
FROM amd64/debian:buster@sha256:108052254277ea53cd807d2782ed3cbe4b9242256af5c7519c6e5692ae2b5d97 AS base

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
    libsgx-ae-id-enclave=1.19.100.3-focal1 \
    libsgx-ae-pce=2.22.100.3-focal1 \
    libsgx-ae-qe3=1.19.100.3-focal1 \
    libsgx-dcap-ql=1.19.100.3-focal1 \
    libsgx-dcap-ql-dev=1.19.100.3-focal1 \
    libsgx-enclave-common=2.22.100.3-focal1 \
    libsgx-headers=2.22.100.3-focal1 \
    libsgx-pce-logic=1.19.100.3-focal1 \
    libsgx-qe3-logic=1.19.100.3-focal1 \
    libsgx-urts=2.22.100.3-focal1 \
    open-enclave=0.19.3 \
    && break; done

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:94e7183b0739140dbd5b639fb7600f0a2299cec5df8780c26d9cb409da5315a9 AS nsmbuild
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
    && break; done

COPY docker/check_hash.sh docker/sha256.* ./

ARG PROTOBUF_PLATFORM=linux-x86_64
ARG PROTOBUF_VERSION=21.8
ARG PROTOBUF_BASE=protoc-${PROTOBUF_VERSION}-${PROTOBUF_PLATFORM}

RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOBUF_BASE}.zip \
	&& /bin/bash ./check_hash.sh ${PROTOBUF_BASE}.zip \
	&& mkdir -p ${PROTOBUF_BASE} \
	&& cd ${PROTOBUF_BASE} \
  && unzip -o ../${PROTOBUF_BASE}.zip \
  && cd .. \
  && mv ${PROTOBUF_BASE} /opt/protobuf

ARG GOLANG_PLATFORM=linux-amd64
ARG GOLANG_VERSION=1.21.3
ARG GOLANG_TAR_GZ=go${GOLANG_VERSION}.${GOLANG_PLATFORM}.tar.gz

RUN wget https://go.dev/dl/${GOLANG_TAR_GZ} \
  && /bin/bash ./check_hash.sh ${GOLANG_TAR_GZ} \
	&& tar xzf ${GOLANG_TAR_GZ} \
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

WORKDIR /src
COPY --from=nsmbuild /build/target/release/libnsm.a /opt/nsm/libnsm.a
COPY --from=nsmbuild /build/target/release/nsm.h    /opt/nsm/nsm.h

CMD ["/bin/bash"]

FROM base AS sgxrun

RUN apt-get update && apt-get install -y \
    libsgx-dcap-default-qpl=1.19.100.3-focal1 \
    libsgx-dcap-default-qpl-dev=1.19.100.3-focal1 \
    curl
COPY docker/sgx_default_qcnl_azure.conf /etc/sgx_default_qcnl.conf
COPY host/main /bin/svr2
COPY enclave/releases/sgx /enclaves
COPY host/cmd/control/control /bin/svr2control

ENTRYPOINT ["/bin/svr2"]

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:94e7183b0739140dbd5b639fb7600f0a2299cec5df8780c26d9cb409da5315a9 AS nsmrun
ADD enclave/build/enclave.nsm /bin/svr2
ENTRYPOINT ["/bin/svr2", "--sock_type=af_vsock"]

FROM alpine@sha256:ff6bdca1701f3a8a67e328815ff2346b0e4067d32ec36b7992c1fdc001dc8517 AS sevrun
COPY enclave/build/enclave.sev /bin/svr2
EXPOSE 27427
ENTRYPOINT ["/bin/svr2", "--sock_type=af_inet"]

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:94e7183b0739140dbd5b639fb7600f0a2299cec5df8780c26d9cb409da5315a9 AS nsmeif
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
