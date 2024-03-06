# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
all: build2

build3: build2 debian3.json
	rm -rf build3
	sed 's/#.*//' debian3.json | packer build /dev/stdin

build2: build1 debian2.json debian2/*
	rm -rf build2
	sed 's/#.*//' debian2.json | packer build /dev/stdin

build1: debian1.json debian1/*
	rm -rf build1
	sed 's/#.*//' debian1.json | packer build /dev/stdin

clean:
	rm -rf build1 build2 build3
