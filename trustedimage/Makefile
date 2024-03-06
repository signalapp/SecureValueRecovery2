# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
SHELL=/bin/bash -o pipefail  # needed for pipefail

all: build/azure_version

build/dir:
	mkdir -p build
	touch build/dir

build/%.json: %.json build/dir
	sed 's/#.*//' $< > $@

build/debian3.out: build/debian3.json build/debian2.out
	rm -rf $@
	packer build $<

build/debian2.out: build/debian2.json build/debian1.out debian2/*
	rm -rf $@
	packer build $<

build/debian1.out: build/debian1.json debian1/* build/dir
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
