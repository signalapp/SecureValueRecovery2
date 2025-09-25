# syntax=docker/dockerfile:1
# To build use:
# docker build -t oebuild .
FROM amd64/debian:bookworm@sha256:e83f38eb264420870d48bccc73f04df5fffc710c66528ad424f857eeff269915 AS base

LABEL description="linux build environment for sgx."

COPY docker/apt.conf docker/sources.list /etc/apt/
RUN rm -rf /etc/apt/sources.list.d/*
COPY docker/sgx_runtime_libraries.sh /tmp/
RUN /tmp/sgx_runtime_libraries.sh

ARG OPENENCLAVE_VERSION=0.19.13
ARG OPENENCLAVE_HASH=10a74d365c1add73b95388f22dad89cd62cbac701dbe935aae39ecf07f29c510
ADD --checksum=sha256:${OPENENCLAVE_HASH} \
    https://github.com/openenclave/openenclave/releases/download/v${OPENENCLAVE_VERSION}/Ubuntu_2204_open-enclave_${OPENENCLAVE_VERSION}_amd64.deb ./
RUN dpkg -i Ubuntu_2204_open-enclave_${OPENENCLAVE_VERSION}_amd64.deb

FROM public.ecr.aws/amazonlinux/amazonlinux:2023.8.20250908.0@sha256:0afbc075facf7bb19482cd244d037222d6f998e8a443106fe245d23008910452 AS amazon

FROM amazon AS nsmbuild
ENV HOST_MACHINE=x86_64
ENV RUST_VERSION=1.89.0
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
    while true; do apt-get update && break; done && \
    while true; do apt-get install -y \
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
      xz-utils \
      libstdc++-12-dev \
    && break; done && apt-get clean

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
ARG GOLANG_VERSION=1.25.1
ARG GOLANG_TAR_GZ=go${GOLANG_VERSION}.${GOLANG_PLATFORM}.tar.gz

ADD --checksum=sha256:7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e https://go.dev/dl/${GOLANG_TAR_GZ} ./
RUN tar xzf ${GOLANG_TAR_GZ} \
  && mv go /opt/

# Rather than ADD --checksum=xxx this file, we wget it within a RUN so the file itself,
# which is quite large, doesn't show up in any intermediate layers.
ARG CLANG_VERSION=11.1.0
ARG LATEST_CLANG_11=${CLANG_VERSION}-x86_64-linux-gnu-ubuntu-20.10
COPY docker/clang+llvm-${LATEST_CLANG_11}.tar.xz.sha256 /tmp
RUN cd /tmp && \
    wget -nv https://github.com/llvm/llvm-project/releases/download/llvmorg-${CLANG_VERSION}/clang+llvm-${LATEST_CLANG_11}.tar.xz && \
    sha256sum -c clang+llvm-${LATEST_CLANG_11}.tar.xz.sha256 && \
    tar xvf clang+llvm-${LATEST_CLANG_11}.tar.xz \
        clang+llvm-${LATEST_CLANG_11}/bin/clang-11 \
        clang+llvm-${LATEST_CLANG_11}/lib/clang/${CLANG_VERSION}/include && \
    mv clang+llvm-${LATEST_CLANG_11} /opt/clang && \
    ln -s /opt/clang/bin/clang-11 /opt/clang/bin/clang++-11 && \
    rm -fv clang+llvm-${LATEST_CLANG_11}.tar.xz

ENV PATH="/opt/clang/bin:/opt/openenclave/bin:/opt/go/bin:/opt/protobuf/bin:${PATH}"
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

ADD --checksum=sha256:c4f2796b10ee886001f0799bc40caea38746403a33c379d77878c4f4683f9b51 https://static.rust-lang.org/dist/rust-1.89.0-x86_64-unknown-linux-gnu.tar.xz /tmp/
RUN apt-get install -y xz-utils && \
    (cd /tmp && tar xJf /tmp/rust-1.89.0-x86_64-unknown-linux-gnu.tar.xz) && \
    (cd /tmp/rust-1.89.0-x86_64-unknown-linux-gnu && ./install.sh) && \
    (rm -fv /tmp/rust-1.89.0-x86_64-unknown-linux-gnu.tar.xz && rm -rf /tmp/rust-1.89.0-x86_64-unknown-linux-gnu)

CMD ["/bin/bash"]

FROM base AS sgxrun

RUN apt-get update && apt-get install -y \
    libsgx-dcap-default-qpl=1.22.100.3-jammy1 \
    libsgx-dcap-default-qpl-dev=1.22.100.3-jammy1 \
    libcurl4 && apt-get clean
COPY host/main /bin/svr2
COPY enclave/releases/sgx /enclaves
COPY host/cmd/control/control /bin/svr3control
RUN ln -s /bin/svr3control /bin/svr2control

ENTRYPOINT ["/bin/svr2"]

FROM amazon AS nsmrun
ADD --chown=0:0 enclave/build/enclave.nsm /bin/svr2
ENTRYPOINT ["/bin/svr2", "--sock_type=af_vsock"]

FROM alpine@sha256:ff6bdca1701f3a8a67e328815ff2346b0e4067d32ec36b7992c1fdc001dc8517 AS sevrun
COPY enclave/build/enclave.sev /bin/svr2
EXPOSE 27427
ENTRYPOINT ["/bin/svr2", "--sock_type=af_inet"]

FROM amazon AS nsmeif
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

FROM amazon AS nsmhost
RUN yum install -y \
    aws-nitro-enclaves-cli.x86_64 \
    jq
COPY docker/nitro_start.sh nitro_start.sh
RUN mkdir /releases
COPY enclave/releases/nitro/* /releases
COPY host/main /bin/svr2
COPY host/cmd/control/control /bin/svr3control
RUN ln -s /bin/svr3control /bin/svr2control
ENTRYPOINT ["./nitro_start.sh"]
