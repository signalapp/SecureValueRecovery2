# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
SHELL=/bin/bash -o pipefail  # needed for pipefail

all: build/gcp_version

build/dir:
	mkdir -p build
	touch build/dir

build/debian2.out: debian2.pkr.hcl build/debian1.out debian2/* ../enclave/build/enclave.gcpsnp ../enclave/build/enclave.azuresnp ../host/main
	rm -rf $@
	packer build $<

build/debian1.out: debian1.pkr.hcl debian1/* build/dir
	rm -rf $@
	packer build $<

clean:
	rm -rf build

build/version: build/debian2.out
	echo "0.$$(date --utc +%Y%m%d.%H%M%S)" > $@

build/azure_version: build/version azure.sh azure_config
	./azure.sh $$(cat build/version)

build/gcp_version: build/version gcp.sh gcp_config
	./gcp.sh $$(cat build/version)
