dockall: docker_all

all: validate host enclave control

MAKE_ARGS ?= --keep-going

validate:
	$(MAKE) $(MAKE_ARGS) -C enclave validate
	$(MAKE) $(MAKE_ARGS) -C host validate
	./check_copyrights.sh

git:
	git submodule init || true
	git submodule update || true

enclave: | git
	$(MAKE) $(MAKE_ARGS) -C enclave all

enclave_test: | git
	$(MAKE) $(MAKE_ARGS) -C enclave test

host: enclave | git
	$(MAKE) $(MAKE_ARGS) -C host all

control: | git
	$(MAKE) $(MAKE_ARGS) -C host control

clean:
	$(MAKE) $(MAKE_ARGS) -C enclave clean
	$(MAKE) $(MAKE_ARGS) -C host clean

dockerbase: | git
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

container: dockerbase
	docker build -f docker/Dockerfile -t svr2_runenv .

enclave_release: docker_enclave_releaser
enclave_releaser: enclave host  # depends on 'host' so its tests will run
	cp -vn enclave/build/enclave.signed "enclave/releases/default.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.signed | fgrep -i mrenclave | cut -d '=' -f2)"
	cp -vn enclave/build/enclave.small "enclave/releases/small.$$(/opt/openenclave/bin/oesign dump -e enclave/build/enclave.small | fgrep -i mrenclave | cut -d '=' -f2)"

.PHONY: all clean enclave host dockersh docker dockerbase git validate enclave_testbin control enclave_release enclave_releaser
