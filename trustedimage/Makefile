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

build/azure_version: azure.sh build/debian2.out azure_config
	./azure.sh

clean:
	rm -rf build
