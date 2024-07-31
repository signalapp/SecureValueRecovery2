# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
OE_INCDIR = $(shell pkg-config oeenclave-clang++ --variable=includedir)
CC=clang-11
GO_TEST_FLAGS ?=

all: build test cmds miniredis
.PHONY: all clean protos build test validate enclave_binaries

build: generated
	go build main.go

enclave_binaries:
	$(MAKE) -C ../enclave build/enclave.test build/enclave.nsm

# -count=1 forces this test to run un-cached, since enclave.test may have changed
# even though Go code has not, and tests may depend on it.
test: build enclave_binaries rustclient
	go test $(GO_TEST_FLAGS) -count=1 ./...

rustclient:
	cd integration/rustclient && cargo build

EDGER8R_FILES=enclave/c/svr2_u.c enclave/c/svr2_u.h enclave/c/svr2_args.h
# This $(firstword) trick allows for grouped targets.
$(filter-out $(firstword $(EDGER8R_FILES)),$(EDGER8R_FILES)): $(firstword $(EDGER8R_FILES))
$(firstword $(EDGER8R_FILES)): ../shared/svr2.edl
	mkdir -p enclave/c
	oeedger8r $< --untrusted \
    --untrusted-dir enclave/c \
		--search-path $(OE_INCDIR) \
		--search-path $(OE_INCDIR)/openenclave/edl/sgx
enclave/c/libsvr2.a: $(EDGER8R_FILES)
	$(CC) -c -o enclave/c/svr2.o $(shell pkg-config oehost-clang --cflags) enclave/c/svr2_u.c
	ar rcs $@ enclave/c/svr2.o

PROTO_FILES = \
  $(patsubst ../shared/proto/%.proto,proto/%.pb.go,$(wildcard ../shared/proto/*.proto)) \
  $(patsubst proto/%.proto,proto/%.pb.go,$(wildcard proto/*.proto)) \
## PROTO_FILES
# This $(firstword) trick allows for grouped targets.
$(filter-out $(firstword $(PROTO_FILES)),$(PROTO_FILES)): $(firstword $(PROTO_FILES))
$(firstword $(PROTO_FILES)): ../shared/proto/*.proto proto/*.proto
	protoc --go_out=. --go_opt=module=github.com/signalapp/svr2 --proto_path=../shared/proto ../shared/proto/*.proto
	protoc --go_out=. --go_opt=module=github.com/signalapp/svr2 --proto_path=../shared/proto --proto_path=proto proto/*.proto
protos: $(PROTO_FILES)
generated: protos enclave/c/libsvr2.a

validate: generated
	go vet ./...
	CHANGES="$$(go fmt ./...)" ; echo "Changes: $$CHANGES" && [ -z "$$CHANGES" ]
 
clean:
	rm -vfr enclave/c
	rm -vfr main
	rm -vf  proto/*.pb.go
	rm -vf  .test_enclave
	rm -vf  enclave/enclave.test

enclave/enclave.test: generated
	(cd enclave && go test -c)

enclave_test_gdb: enclave/enclave.test ../enclave/build/enclave.test
	(cd enclave && /opt/openenclave/bin/oegdb enclave.test)

miniredis:
	(cd miniredis && go build miniredis.go)

cmds: generated
	(cd cmd/control && go build)
	(cd cmd/get_sev_chain && go build)
	(cd cmd/svr2client && go build)
	(cd cmd/svr3client && go build)
	(cd cmd/svr3gcp && go build)

get_sev_chain: generated
	(cd cmd/get_sev_chain && go build)
