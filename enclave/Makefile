all: test build sign

MAKEFILTER=| (grep --line-buffered -v '^make\[' || true)

include Makefile.base

.PHONY: all build sign clean sign protos validate generatem

build: build/enclave.bin build/enclave.nsm

sign: build/enclave.signed build/enclave.test build/enclave.small

PROTO_FILES= \
  $(patsubst ../shared/proto/%.proto,build/proto/%.pb.cc,$(wildcard ../shared/proto/*.proto)) \
  $(patsubst ../shared/proto/%.proto,build/proto/%.pb.h,$(wildcard ../shared/proto/*.proto)) \
  $(patsubst proto/%.proto,build/proto/%.pb.cc,$(wildcard proto/*.proto)) \
  $(patsubst proto/%.proto,build/proto/%.pb.h,$(wildcard proto/*.proto)) \
## PROTO_FILES
protos: $(PROTO_FILES)

build/proto:
	$(QUIET) echo -e "MKDIR $@"
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
build/noise-c/NSM.a: build/libsodium/NSM.a | build/noise-c/SGX.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D)
	$(QUIET) (cd noise-c && \
	 ./autogen.sh && \
   libsodium_CFLAGS=-I$$PWD/../build/libsodium/NSM.a.dir/include/ libsodium_LIBS=$$PWD/../build/libsodium/NSM.a \
	 CC=$(CC) CFLAGS="$(NSM_CFLAGS) -I$(shell ./find_header.sh $(CC) immintrin.h)" ./configure --with-libsodium && \
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
build/boringssl/NSM.a: | build/boringssl/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd boringssl && rm -rf build && mkdir build && cd build && CC=$(CC) CXX=$(CXX) CFLAGS="$(NSM_CFLAGS)" CXXFLAGS="$(NSM_CXXFLAGS)" LDFLAGS="$(NSM_LDFLAGS)" cmake .. && $(MAKE) crypto) $(QUIET_OUT)
	$(QUIET) cp -v boringssl/build/crypto/libcrypto.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"

build/tinycbor/TEST.a:
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd tinycbor && $(MAKE) clean && $(MAKE) CC=$(CC) CXX=$(CXX) CFLAGS="$(TEST_CFLAGS)" CXXFLAGS="$(TEST_CXXFLAGS)" LDFLAGS="$(TEST_LDFLAGS)") $(QUIET_OUT)
	$(QUIET) cp -v tinycbor/lib/libtinycbor.a $@ $(QUIET_OUT)
	$(QUIET) echo -e "BUILT\t$@"
build/tinycbor/NSM.a: | build/tinycbor/TEST.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $(@D) $(QUIET_OUT)
	$(QUIET) (cd tinycbor && $(MAKE) clean && $(MAKE) CC=$(CC) CXX=$(CXX) CFLAGS="$(NSM_CFLAGS)" CXXFLAGS="$(NSM_CXXFLAGS)" LDFLAGS="$(NSM_LDFLAGS)") $(QUIET_OUT)
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
build/libsodium/NSM.a: | build/libsodium/SGX.a
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) mkdir -p $@.dir $(@D)
	$(QUIET) (cd libsodium && (git clean -fx || true) && ./configure \
  CFLAGS="$(NSM_CFLAGS) $(LIBSODIUM_UNDEFS)" \
  CXXFLAGS="$(NSM_CXXFLAGS) $(LIBSODIUM_UNDEFS)" \
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
build/%/NSM.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=NSM $(MAKEFILTER)
build/%/TEST.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=TEST $(MAKEFILTER)
build/%/HOST.a: generated
	$(QUIET) $(MAKE) -f Makefile.subdir DIR=$* ENV=HOST $(MAKEFILTER)
.PHONY: build/%/SGX.a build/%/TEST.a build/%/HOST.a build/%/NSM.a

# All libraries which will become part of enclave.bin.  If A depends on B, then A should be added before B.
SGX_LIBRARIES = \
  svr2 \
  ecalls \
  core \
  timeout \
  client \
  db \
  raft \
  groupclock \
  peers \
  peerid \
  sender \
  util \
  context \
  hmac \
  noise \
  noise-c \
  noisewrap \
  env \
  env/sgx \
  sip \
  attestation/oe \
  metrics \
  proto \
  protobuf-lite \
  libsodium \
## SGX_LIBRARIES

build/enclave.bin: $(patsubst %,build/%/SGX.a,$(SGX_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(SGX_LDFLAGS) $^ $(SGX_LDFLAGS)

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
  nitromain \
  core \
  timeout \
  client \
  db \
  raft \
  groupclock \
  peers \
  peerid \
  sender \
  util \
  hmac \
  noise \
  noise-c \
  noisewrap \
  env \
  env/nsm \
  sip \
  socketwrap \
  attestation/nitro \
  context \
  metrics \
  proto \
  protobuf-lite \
  libsodium \
  tinycbor \
  boringssl \
## NSM_LIBRARIES

build/enclave.nsm: $(patsubst %,build/%/NSM.a,$(NSM_LIBRARIES))
	$(QUIET) echo -e "BUILD\t$@"
	$(QUIET) $(CXX) -o $@ $(NSM_LDFLAGS) $^ $(NSM_LDFLAGS)

clean:
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

%.test.out: %.test
	$(QUIET) echo -e "TEST\t$<"
	$(QUIET) ./$^ --gtest_color=yes &>$@ || (cat $@; false)
	$(QUIET) echo -e "TEST\xE2\x9c\x85\t$<"

build/testhost/libsvr2.a: 
	$(QUIET) mkdir -p $(@D)
	$(CC) -c -o build/testhost/svr2.o $(HOST_CFLAGS) ../host/enclave/c/svr2_u.c
	ar rcs $@ build/testhost/svr2.o

build/testhost.bin: testhost/testhost.cc build/testhost/libsvr2.a build/attestation/HOST.a build/metrics/HOST.a build/proto/HOST.a build/protobuf-lite/HOST.a
	$(CXX) -o $@ $(HOST_CXXFLAGS) $(HOST_LDFLAGS) $^ $(HOST_LDFLAGS)

.testdepends: $(shell find ./ -type f | grep /tests/ | grep cc$)
	$(QUIET) ./test_deps.sh $(QUIET_OUT)
include .testdepends

test:
validate:
