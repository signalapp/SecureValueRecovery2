# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
dockall: docker_all

.PHONY: host
.PHONY: enclave

all: validate host enclave cmds

MAKE_ARGS ?=
ARCH ?= $(shell arch)
ifeq ($(ARCH),arm64)
	MAKE_ARGS += 'GO_TEST_FLAGS=-short' # long tests can cause qemu crashes in x86 emulation
endif

validate:
	$(MAKE) $(MAKE_ARGS) -C enclave validate
	$(MAKE) $(MAKE_ARGS) -C host validate
	./check_copyrights.sh

git:
	git submodule init || true
	git submodule update --recursive --init || true
	git submodule update --recursive || true

ETARGET ?= all

enclave: | git
	$(MAKE) $(MAKE_ARGS) -C enclave $(ETARGET)

enclave_test: | git
	$(MAKE) $(MAKE_ARGS) -C enclave test

enclave_valgrind: enclave_test | git
	$(MAKE) $(MAKE_ARGS) -C enclave valgrind

host: enclave | git
	$(MAKE) $(MAKE_ARGS) -C host all

cmds: | git
	$(MAKE) $(MAKE_ARGS) -C host cmds

clean:
	$(MAKE) $(MAKE_ARGS) -C enclave clean
	$(MAKE) $(MAKE_ARGS) -C host clean
	rm -rf docker/build
	rm -rf .cargohome/* .cargohome/.*cache* .cargotarget/*
	git submodule foreach --recursive git clean -fxd

dockerbase: | git
	[ "" != "$(SKIP_DOCKER_BUILD)" ] || \
	    docker buildx build $(DOCKER_BUILD_ARGS) --load -f docker/Dockerfile -t svr2_buildenv --target=builder .

enclave_releaser: enclave host  # depends on 'host' so its tests will run
	cp -vn enclave/build/enclave.signed "enclave/releases/sgx/default.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.signed | fgrep -i mrenclave | cut -d '=' -f2)"
	cp -vn enclave/build/enclave.small "enclave/releases/sgx/small.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.small | fgrep -i mrenclave | cut -d '=' -f2)"
	cp -vn enclave/build/enclave.medium "enclave/releases/sgx/medium.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.medium | fgrep -i mrenclave | cut -d '=' -f2)"


### Remaining targets run docker/packer and should be run directly on the host (not with docker_) ###

OS:=$(shell uname -s)
ifeq ($(OS), Linux)
	PARALLEL ?= $(shell cat /proc/cpuinfo | grep '^cpu cores' | awk 'BEGIN { sum = 1 } { sum += $$4 } END { print sum }')
endif
ifeq ($(OS), Darwin)
	PARALLEL ?= $(shell sysctl -n hw.ncpu)
endif
DOCKER_MAKE_ARGS ?= -j$(PARALLEL) MAKE_ARGS='$(MAKE_ARGS)'
DOCKER_RUN_ARGS ?=
DOCKER_BUILD_ARGS ?= --platform=linux/amd64
docker_%: dockerbase
	docker run \
	  -v "$$(pwd):/src" \
	  -u "$$(id -u):$$(id -g)" \
	  $(DOCKER_RUN_ARGS) \
	  svr2_buildenv /bin/bash -c "make V=$(V) $(DOCKER_MAKE_ARGS) $*"

dockersh: dockerbase
	docker run --rm -it \
	  -v "$$(pwd):/src" \
	  -u "$$(id -u):$$(id -g)" \
	  -e "TERM=xterm-256color" \
	  $(DOCKER_RUN_ARGS) \
	  svr2_buildenv

docker/build/nsmrun.tar: docker_enclave
	mkdir -p docker/build
	docker run --rm \
		-v $${PWD}:/workspace \
		gcr.io/kaniko-project/executor@sha256:7914350eda14b43f3dcc6925afca88d6b7ba5dff13d221bb70ef44d4da73a1e8 \
		--dockerfile /workspace/docker/Dockerfile --context dir:///workspace/ \
		--reproducible --no-push --skip-unused-stages \
		--destination svr2_nsmrun:latest \
		--custom-platform linux/amd64 \
		--tar-path /workspace/docker/build/nsmrun.tar \
		--target nsmrun

nsmrun: docker/build/nsmrun.tar
	docker load < docker/build/nsmrun.tar

enclave_release: docker_enclave_releaser nsmrun
	docker buildx build $(DOCKER_BUILD_ARGS) --load -f docker/Dockerfile -t svr2_nsmeif --target=nsmeif .
	docker buildx build $(DOCKER_BUILD_ARGS) --load -f docker/Dockerfile -t svr2_sgxrun --target=sgxrun .
	docker run $(DOCKER_RUN_ARGS) --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $${PWD}/enclave/releases/nitro:/out/ \
	  -u "0:0" \
	  -e "TERM=xterm-256color" \
    -e "DOCKER_IMAGE=svr2_nsmrun:latest" \
    -e "OUTPUT_DIR=/out" \
    -e "CHOWN_TO=$$(id -u):$$(id -g)" \
    svr2_nsmeif:latest
	docker buildx build $(DOCKER_BUILD_ARGS) --load -f docker/Dockerfile -t svr2_nsmhost --target=nsmhost .

.PHONY: trustedimage
trustedimage:
	$(MAKE) -C trustedimage

