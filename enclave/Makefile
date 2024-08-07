# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
all: test build sign

MAKEFILTER=| (grep --line-buffered -v '^make\[' || true)

test:

include Makefile.base
.testdepends: $(shell find ./ -wholename '*/tests/*.cc' -o -wholename '*/tests')
	$(QUIET) echo -e "GEN\t.testdepends"
	$(QUIET) ./test_deps.sh $(QUIET_OUT)
include .testdepends

.PHONY: build

build: build/enclave.bin build/enclave.nsm build/enclave.gcpsnp build/attest.gcpsnp build/enclave.azuresnp build/attest.azuresnp

sign: build/enclave.signed build/enclave.test build/enclave.small

PROTO_FILES= \
  $(patsubst ../shared/proto/%.proto,build/proto/%.pb.cc,$(wildcard ../shared/proto/*.proto)) \
  $(patsubst ../shared/proto/%.proto,build/proto/%.pb.h,$(wildcard ../shared/proto/*.proto)) \
  $(patsubst proto/%.proto,build/proto/%.pb.cc,$(wildcard proto/*.proto)) \
  $(patsubst proto/%.proto,build/proto/%.pb.h,$(wildcard proto/*.proto)) \
## PROTO_FILES
protos: $(PROTO_FILES)

build/proto:
	$(QUIET) echo -e "MKDIR\t$@"
	$(QUIET) mkdir -p $@
build/proto/%.pb.h build/proto/%.pb.cc: proto/%.proto | build/proto
	$(QUIET) echo -e "PROTO\t$^"
	$(QUIET) protoc --proto_path=../shared/proto --proto_path=proto --cpp_out=build/proto $^
build/proto/%.pb.h build/proto/%.pb.cc: ../shared/proto/%.proto | build/proto
	$(QUIET) echo -e "PROTO\t$^"
	$(QUIET) protoc --proto_path=../shared/proto --cpp_out=build/proto $^

build/gtest/TEST.a:
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=gtest ENV=TEST ADDITIONAL_CFLAGS="-I$(CURDIR)/googletest/googletest" $(MAKEFILTER)

build/noise-c/TEST.a: build/libsodium/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) (cd noise-c && \
	 ./autogen.sh && \
   libsodium_CFLAGS=-I$$PWD/../build/libsodium/TEST.a.dir/include/ libsodium_LIBS=$$PWD/../build/libsodium/TEST.a \
	 CC=$(CC) CFLAGS="$(TEST_CFLAGS) -I$(shell ./find_header.sh $(CC) immintrin.h)" ./configure --with-libsodium && \
   $(MAKE) clean && \
	 $(MAKE)) $(QUIET_OUT)
	$(QUIET) cp noise-c/src/protocol/libnoiseprotocol.a $@
	$(QUIET) echo -e "BUILT\t$@"
build/noise-c/SGX.a: build/libsodium/SGX.a | build/noise-c/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) (cd noise-c && \
	 ./autogen.sh && \
   libsodium_CFLAGS=-I$$PWD/../build/libsodium/SGX.a.dir/include/ libsodium_LIBS=$$PWD/../build/libsodium/SGX.a \
	 CC=$(CC) CFLAGS="$(SGX_CFLAGS) -I$(shell ./find_header.sh $(CC) immintrin.h)" ./configure --with-libsodium && \
   $(MAKE) clean && \
	 $(MAKE)) $(QUIET_OUT)
	$(QUIET) cp noise-c/src/protocol/libnoiseprotocol.a $@
	$(QUIET) echo -e "BUILT\t$@"
build/noise-c/X86.a: build/libsodium/X86.a | build/noise-c/SGX.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) (cd noise-c && \
	 ./autogen.sh && \
   libsodium_CFLAGS=-I$$PWD/../build/libsodium/X86.a.dir/include/ libsodium_LIBS=$$PWD/../build/libsodium/X86.a \
	 CC=$(CC) CFLAGS="$(X86_CFLAGS) -I$(shell ./find_header.sh $(CC) immintrin.h)" ./configure --with-libsodium && \
   $(MAKE) clean && \
	 $(MAKE)) $(QUIET_OUT)
	$(QUIET) cp noise-c/src/protocol/libnoiseprotocol.a $@
	$(QUIET) echo -e "BUILT\t$@"

build/boringssl/TEST.a:
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd boringssl && rm -rf build && mkdir build && cd build && CC=$(CC) CXX=$(CXX) CFLAGS="$(TEST_CFLAGS)" CXXFLAGS="$(TEST_CXXFLAGS)" LDFLAGS="$(TEST_LDFLAGS)" cmake .. && $(MAKE) crypto) $(QUIET_OUT)
	$(QUIET) cp -v boringssl/build/crypto/libcrypto.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"
build/boringssl/X86.a: | build/boringssl/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd boringssl && rm -rf build && mkdir build && cd build && CC=$(CC) CXX=$(CXX) CFLAGS="$(X86_CFLAGS)" CXXFLAGS="$(X86_CXXFLAGS)" LDFLAGS="$(X86_LDFLAGS)" cmake .. && $(MAKE) crypto) $(QUIET_OUT)
	$(QUIET) cp -v boringssl/build/crypto/libcrypto.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"

build/tinycbor/TEST.a:
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd tinycbor && $(MAKE) clean && $(MAKE) CC=$(CC) CXX=$(CXX) CFLAGS="$(TEST_CFLAGS)" CXXFLAGS="$(TEST_CXXFLAGS)" LDFLAGS="$(TEST_LDFLAGS)") $(QUIET_OUT)
	$(QUIET) cp -v tinycbor/lib/libtinycbor.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"
build/tinycbor/X86.a: | build/tinycbor/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd tinycbor && $(MAKE) clean && $(MAKE) CC=$(CC) CXX=$(CXX) CFLAGS="$(X86_CFLAGS)" CXXFLAGS="$(X86_CXXFLAGS)" LDFLAGS="$(X86_LDFLAGS)") $(QUIET_OUT)
	$(QUIET) cp -v tinycbor/lib/libtinycbor.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"

# libsodium's ./configure script incorrectly detects that mmap, mlock, madvise, mprotect,
# and raise are all available, when in fact they are not in the enclave.  This set of flags
# allows us to undo that.
LIBSODIUM_UNDEFS=-UHAVE_MMAP -UHAVE_MLOCK -UHAVE_MADVISE -UHAVE_MPROTECT -UHAVE_RAISE
##LIBSODIUM_UNDEFS
build/libsodium/TEST.a:
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $@.dir $(@D)
	$(QUIET) (cd libsodium && (git clean -fx || true) && ./configure \
  CFLAGS="$(TEST_CFLAGS)" \
  CXXFLAGS="$(TEST_CXXFLAGS)" \
  CC=$(CC) CXX=$(CXX) --prefix=$$PWD/../$@.dir && $(MAKE) clean && $(MAKE) install) $(QUIET_OUT)
	$(QUIET) ln -s $$PWD/$@.dir/lib/libsodium.a $@
	$(QUIET) echo -e "BUILT\t$@"
build/libsodium/SGX.a: | build/libsodium/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $@.dir $(@D)
	$(QUIET) (cd libsodium && (git clean -fx || true) && ./configure \
  CFLAGS="$(SGX_CFLAGS) $(LIBSODIUM_UNDEFS)" \
  CXXFLAGS="$(SGX_CXXFLAGS) $(LIBSODIUM_UNDEFS)" \
  CC=$(CC) CXX=$(CXX) --prefix=$$PWD/../$@.dir && $(MAKE) clean && $(MAKE) install) $(QUIET_OUT)
	$(QUIET) ln -s $$PWD/$@.dir/lib/libsodium.a $@
	$(QUIET) echo -e "BUILT\t$@"
build/libsodium/X86.a: | build/libsodium/SGX.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $@.dir $(@D)
	$(QUIET) (cd libsodium && (git clean -fx || true) && ./configure \
  CFLAGS="$(X86_CFLAGS) $(LIBSODIUM_UNDEFS)" \
  CXXFLAGS="$(X86_CXXFLAGS) $(LIBSODIUM_UNDEFS)" \
  CC=$(CC) CXX=$(CXX) --prefix=$$PWD/../$@.dir && $(MAKE) clean && $(MAKE) install) $(QUIET_OUT)
	$(QUIET) ln -s $$PWD/$@.dir/lib/libsodium.a $@
	$(QUIET) echo -e "BUILT\t$@"

EDGER8R_FILES=build/svr2/svr2_t.h build/svr2/svr2_t.c build/svr2/svr2_args.h
# This $(firstword) trick allows for grouped targets.
$(filter-out $(firstword $(EDGER8R_FILES)),$(EDGER8R_FILES)): $(firstword $(EDGER8R_FILES))
$(firstword $(EDGER8R_FILES)): ../shared/svr2.edl
	$(QUIET) echo -e "EDGER8\t$(EDGER8R_FILES)"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) $(OE_EDGER8R) $< --trusted \
    --trusted-dir build/svr2 \
		--search-path $(OE_INCDIR) \
		--search-path $(OE_INCDIR)/openenclave/edl/sgx $(QUIET_OUT)

generated: $(EDGER8R_FILES) $(PROTO_FILES)
build/%/SGX.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=SGX $(MAKEFILTER)
build/%/X86.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=X86 $(MAKEFILTER)
build/%/TEST.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=TEST $(MAKEFILTER)
build/%/HOST.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=HOST $(MAKEFILTER)
.PHONY: build/%/SGX.a build/%/TEST.a build/%/HOST.a build/%/X86.a

CORE_LIBRARIES_PRE_ENV = \
  core \
  timeout \
  client \
  db \
  merkle \
  raft \
  groupclock \
  peers \
  peerid \
  minimums \
  sender \
  util \
  context \
  hmac \
  sha \
  ristretto \
  noise \
  noise-c \
  noisewrap \
  env \
## CORE_LIBRARIES_PRE_ENV
CORE_LIBRARIES_POST_ENV = \
  sip \
  metrics \
  proto \
  protobuf-lite \
  libsodium \
## CORE_LIBRARIES_POST_ENV

# All libraries which will become part of enclave.bin.  If A depends on B, then A should be added before B.
SGX_LIBRARIES = \
  svr2 \
  ecalls \
  $(CORE_LIBRARIES_PRE_ENV) \
  env/sgx \
  attestation/oe \
  $(CORE_LIBRARIES_POST_ENV) \
## SGX_LIBRARIES

build/enclave.bin: $(patsubst %,build/%/SGX.a,$(SGX_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(SGX_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(SGX_LDFLAGS)

build/enclave.signed: build/enclave.bin build/public.pem build/private.pem svr2.conf
	$(QUIET) echo -e "SIGN\t$@"
	$(QUIET) $(OE_DIR)/bin/oesign sign -e $< -c svr2.conf -k build/private.pem -o $@ $(QUIET_OUT)

build/enclave.small: build/enclave.bin build/public.pem build/private.pem svr2_small.conf
	$(QUIET) echo -e "SIGN\t$@"
	$(QUIET) $(OE_DIR)/bin/oesign sign -e $< -c svr2_small.conf -k build/private.pem -o $@ $(QUIET_OUT)

build/enclave.test: build/enclave.bin build/public.pem build/private.pem svr2_test.conf
	$(QUIET) echo -e "SIGN\t$@"
	$(QUIET) $(OE_DIR)/bin/oesign sign -e $< -c svr2_test.conf -k build/private.pem -o $@ $(QUIET_OUT)

NSM_LIBRARIES = \
  socketmain \
  $(CORE_LIBRARIES_PRE_ENV) \
  env/nsm \
  attestation/nitro \
  env/socket \
  socketwrap \
  $(CORE_LIBRARIES_POST_ENV) \
  tinycbor \
  boringssl \
## NSM_LIBRARIES

build/enclave.nsm: $(patsubst %,build/%/X86.a,$(NSM_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(X86_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(X86_LDFLAGS)

GCPSNP_LIBRARIES = \
  $(CORE_LIBRARIES_PRE_ENV) \
  env/gcpsnp \
  env/socket \
  attestation/sev \
  attestation/tpm2 \
  attestation/tpm2snp \
  fs \
  socketwrap \
  $(CORE_LIBRARIES_POST_ENV) \
  boringssl \
## GCPSNP_LIBRARIES

build/enclave.gcpsnp: build/socketmain/X86.a $(patsubst %,build/%/X86.a,$(GCPSNP_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(X86_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(X86_LDFLAGS)

build/attest.gcpsnp: build/initmain/X86.a $(patsubst %,build/%/X86.a,$(GCPSNP_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(X86_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(X86_LDFLAGS)

AZURESNP_LIBRARIES = \
  $(CORE_LIBRARIES_PRE_ENV) \
  env \
  env/azuresnp \
  env/socket \
  fs \
  attestation/sev \
  attestation/tpm2 \
  attestation/tpm2snp \
  socketwrap \
  $(CORE_LIBRARIES_POST_ENV) \
  boringssl \
## AZURESNP_LIBRARIES

build/enclave.azuresnp: build/socketmain/X86.a $(patsubst %,build/%/X86.a,$(AZURESNP_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(X86_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(X86_LDFLAGS)

build/attest.azuresnp: build/initmain/X86.a $(patsubst %,build/%/X86.a,$(AZURESNP_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(X86_LDFLAGS) -Wl,--start-group $^ -Wl,--end-group $(X86_LDFLAGS)

clean:
	$(QUIET) echo CLEAN
	$(QUIET) (cd protobuf ; make clean ; git clean -fx ; true) $(QUIET_OUT)
	$(QUIET) (cd noise-c ; make clean ; git clean -fx ; true) $(QUIET_OUT)
	$(QUIET) (cd SipHash ; make clean ; git clean -fx ; true) $(QUIET_OUT)
	$(QUIET) (cd boringssl ; make clean ; git clean -fx ; true) $(QUIET_OUT)
	$(QUIET) rm -vfr build $(QUIET_OUT)
	$(QUIET) rm -vf .testdepends $(QUIET_OUT)

build/private.pem:
	$(QUIET) echo -e "KEY\t$@"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) openssl genrsa -out $@ -3 3072 $(QUIET_OUT)
build/public.pem: build/private.pem
	$(QUIET) echo -e "KEY\t$@"
	$(QUIET) openssl rsa -in $< -pubout -out $@ $(QUIET_OUT)

%.test.out %.test.success: %.test
	$(QUIET) echo -e "TEST\t$<"
	$(QUIET) ./$^ --gtest_color=yes &>$*.test.out || (cat $*.test.out; false)
	$(QUIET) echo -e "TEST\xE2\x9c\x85\t$<"
	$(QUIET) touch $*.test.success

%.test.valgrind: %.test
	$(QUIET) echo -e "GRIND\t$<"
	$(QUIET) valgrind --tool=memcheck --leak-check=full --error-exitcode=3 -s --track-origins=yes ./$^ &>$@ || (cat $@; false)
	$(QUIET) echo -e "GRIND\xE2\x9c\x85\t$<"

build/testhost/libsvr2.a: 
	$(QUIET) mkdir -p $(@D)
	$(CC) -c -o build/testhost/svr2.o $(HOST_CFLAGS) ../host/enclave/c/svr2_u.c
	ar rcs $@ build/testhost/svr2.o

build/testhost.bin: testhost/testhost.cc build/testhost/libsvr2.a build/attestation/HOST.a build/metrics/HOST.a build/proto/HOST.a build/protobuf-lite/HOST.a
	$(CXX) -o $@ $(HOST_CXXFLAGS) $(HOST_LDFLAGS) $^ $(HOST_LDFLAGS)

validate:

valgrind:
