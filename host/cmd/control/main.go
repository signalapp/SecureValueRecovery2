// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/web/client"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

var (
	addr   = flag.String("addr", "localhost:8081", "Address (hostname:port) where control server is listening")
	binary = flag.Bool("bin", false, "If true, assume a binary formatted proto file. Otherwise, protojson")
	mode   = flag.String("mode", "command", "One of 'command' or 'status'")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Issue a control command for a HostToEnclaveRequest proto \n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] proto_filename \n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	cc := &client.ControlClient{Addr: *addr}
	switch *mode {
	case "command":
		sendCommand(cc)
	case "status":
		if err := getStatus(cc); err != nil {
			log.Fatal(err)
		}
		log.Println("success")
	}
}

func sendCommand(cc *client.ControlClient) {
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	bs, err := requestBody(flag.Args()[0])
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

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

func getStatus(cc *client.ControlClient) error {
	peers := map[peerid.PeerID]*pb.PeerEntry{}
	peerResp, err := cc.Peers()
	if err != nil {
		log.Printf("Unable to get peers: %v", err)
	} else {
		for _, p := range peerResp.Entries {
			pid, err := peerid.Make(p.Id)
			if err != nil {
				return fmt.Errorf("Invalid peer ID %x: %v", p.Id, err)
			}
			peers[pid] = p.Entry
		}
	}
	resp, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_GetEnclaveStatus{GetEnclaveStatus: true},
	})
	if err != nil {
		return fmt.Errorf("getting status: %w", err)
	}
	status := resp.Inner.(*pb.HostToEnclaveResponse_GetEnclaveStatusReply).GetEnclaveStatusReply
	log.Printf("Status: %v\n", status)
	fmt.Printf("Raft state: %v\n", status.RaftState)
	fmt.Printf("\n")
	fmt.Printf("PeerID,Addr,Role,ConnState,Hostname\n")
	for _, peer := range status.Peers {
		pid, err := peerid.Make(peer.PeerId)
		if err != nil {
			return fmt.Errorf("invalid status peer ID %x: %v", peer.PeerId, err)
		}
		role := "unknown"
		switch {
		case peer.IsLeader:
			role = "LEADER"
		case peer.IsVoting:
			role = "VOTER"
		case peer.InRaft:
			role = "non-voter"
		default:
			role = "none"
		}
		connectionState := "unknown"
		switch {
		case peer.Me:
			connectionState = "ME"
		case peer.ConnectionStatus != nil:
			connectionState = peer.ConnectionStatus.State.String()
		}
		addr := "unknown"
		hostname := "unknown"
		if entry := peers[pid]; entry != nil {
			addr = entry.Addr
			if name, err := net.LookupAddr(strings.Split(addr, ":")[0]); err != nil && len(name) > 0 {
				hostname = name[0]
			}
		}
		fmt.Printf("%s,%s,%s,%s,%s\n", pid, addr, role, connectionState, hostname)
	}
	return nil
}
