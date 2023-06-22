// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Binary miniredis sets up a usable Redis port at --addr, good for simple local testing.
package main

import (
	"flag"
	"log"

	"github.com/alicebob/miniredis/v2"
)

var (
	addr = flag.String("addr", "localhost:6379", "MiniRedis bind address")
)

func main() {
	flag.Parse()
	r := miniredis.NewMiniRedis()
	if err := r.StartAddr(*addr); err != nil {
		log.Fatal(err)
	}
	select {}
}
