dockall: docker_all

.PHONY: host
.PHONY: enclave

all: validate host enclave cmds

MAKE_ARGS ?=

validate:
	$(MAKE) $(MAKE_ARGS) -C enclave validate
	$(MAKE) $(MAKE_ARGS) -C host validate
	./check_copyrights.sh

git:
	git submodule init || true
	git submodule update || true

ETARGET ?= all

enclave: | git
	$(MAKE) $(MAKE_ARGS) -C enclave $(ETARGET)

enclave_test: | git
	$(MAKE) $(MAKE_ARGS) -C enclave test

host: enclave | git
	$(MAKE) $(MAKE_ARGS) -C host all

cmds: | git
	$(MAKE) $(MAKE_ARGS) -C host cmds

clean:
	$(MAKE) $(MAKE_ARGS) -C enclave clean
	$(MAKE) $(MAKE_ARGS) -C host clean

dockerbase: | git
	[ "" != "$(SKIP_DOCKER_BUILD)" ] || \
	    docker build -f docker/Dockerfile -t svr2_buildenv --target=builder .

PARALLEL ?= $(shell cat /proc/cpuinfo | grep '^cpu cores' | awk 'BEGIN { sum = 1 } { sum += $$4 } END { print sum }')
DOCKER_MAKE_ARGS ?= -j$(PARALLEL) MAKE_ARGS="$(MAKE_ARGS)"
ARCH ?= $(shell arch)
ifeq ($(ARCH),arm64)
	DOCKER_MAKE_ARGS += 'GO_TEST_FLAGS=-short' # long tests can cause qemu crashes in x86 emulation
endif
DOCKER_ARGS ?=
docker_%: dockerbase
	docker run \
	  -v "$$(pwd):/src" \
	  -u "$$(id -u):$$(id -g)" \
	  $(DOCKER_ARGS) \
	  svr2_buildenv /bin/bash -c "make V=$(V) $(DOCKER_MAKE_ARGS) $*"

dockersh: dockerbase
	docker run --rm -it \
	  -v "$$(pwd):/src" \
	  -u "$$(id -u):$$(id -g)" \
	  -e "TERM=xterm-256color" \
	  $(DOCKER_ARGS) \
	  svr2_buildenv

enclave_release: docker_enclave_releaser
	docker build -f docker/Dockerfile -t svr2_nsmrun --target=nsmrun .
	docker build -f docker/Dockerfile -t svr2_nsmeif --target=nsmeif .
	docker build -f docker/Dockerfile -t svr2_nsmhost --target=nsmhost .
	docker build -f docker/Dockerfile -t svr2_sgxrun --target=sgxrun .
	docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $${PWD}/enclave/releases/nitro:/out/ \
	  -u "0:0" \
	  -e "TERM=xterm-256color" \
    -e "DOCKER_IMAGE=svr2_nsmrun:latest" \
    -e "OUTPUT_DIR=/out" \
    -e "CHOWN_TO=$$(id -u):$$(id -g)" \
    svr2_nsmeif:latest

enclave_releaser: enclave host  # depends on 'host' so its tests will run
	cp -vn enclave/build/enclave.signed "enclave/releases/sgx/default.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.signed | fgrep -i mrenclave | cut -d '=' -f2)"
	cp -vn enclave/build/enclave.small "enclave/releases/sgx/small.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.small | fgrep -i mrenclave | cut -d '=' -f2)"

