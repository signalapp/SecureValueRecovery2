// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/signalapp/svr2/web/client"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

var (
	addr   = flag.String("addr", "localhost:8081", "Address (hostname:port) where control server is listening")
	binary = flag.Bool("bin", false, "If true, assume a binary formatted proto file. Otherwise, protojson")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Issue a control command for a HostToEnclaveRequest proto \n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] proto_filename \n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	bs, err := requestBody(flag.Args()[0])
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

	cc := client.ControlClient{Addr: *addr}
	resp, err := cc.DoJSON(bs)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "successfully executed control request")
	fmt.Println(protojson.Format(resp))
}

func requestBody(filename string) ([]byte, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file : %v", err)
	}

	request := pb.HostToEnclaveRequest{}
	if *binary {
		err = proto.Unmarshal(bs, &request)
	} else {
		err = protojson.Unmarshal(bs, &request)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto : %v", err)
	}
	if !*binary {
		return bs, nil
	}
	if bs, err = protojson.Marshal(&request); err != nil {
		return nil, fmt.Errorf("failed to marshal proto : %v", err)
	}
	return bs, nil
}
