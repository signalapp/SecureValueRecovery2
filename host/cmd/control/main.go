// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/web/client"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

type command struct {
	f           func(cc *client.ControlClient) error
	description string
	fs          *flag.FlagSet
}

var (
	args struct {
		addr    string
		command struct {
			binary   bool
			filename string
		}
		resetPeer struct {
			id peerid.PeerID
		}
		connectPeer struct {
			id peerid.PeerID
		}
		pingPeer struct {
			id    peerid.PeerID
			count int
		}
		setLogLevel struct {
			level string
		}
		metrics struct {
			updateEnvStats bool
		}
	}
	commands = map[string]*command{
		"command": &command{
			f:           sendCommand,
			description: "Parse a command from --filename as JSON or (if --binary is set) binary proto and send it as a command",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("command", flag.ExitOnError)
				fs.BoolVar(&args.command.binary, "bin", false, "If true, assume a binary formatted proto file. Otherwise, protojson")
				fs.StringVar(&args.command.filename, "filename", "", "Filename to read from")
				return fs
			}(),
		},
		"status": &command{
			f:           getStatus,
			description: "Print information about the status of all replicas as known by --addr",
			fs:          flag.NewFlagSet("status", flag.ExitOnError),
		},
		"relinquishLeadership": &command{
			f:           relinquishLeadership,
			description: "Request that --addr no longer be LEADER",
			fs:          flag.NewFlagSet("relinquishLeadership", flag.ExitOnError),
		},
		"resetPeer": &command{
			f:           resetPeer,
			description: "Request that --addr reset the peer connection to --id",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("resetPeer", flag.ExitOnError)
				fs.Var(&args.resetPeer.id, "id", "Peer ID (hex) to reset")
				return fs
			}(),
		},
		"connectPeer": &command{
			f:           connectPeer,
			description: "Request that --addr connect to --id.  Will have no effect if --addr's connection to --id is already in a CONNECTING or CONNECTED state",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("connectPeer", flag.ExitOnError)
				fs.Var(&args.connectPeer.id, "id", "Peer ID (hex) to connect")
				return fs
			}(),
		},
		"pingPeer": &command{
			f:           pingPeer,
			description: "Request that --addr ping --id.",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("pingPeer", flag.ExitOnError)
				fs.Var(&args.pingPeer.id, "id", "Peer ID (hex) to ping")
				fs.IntVar(&args.pingPeer.count, "count", 1, "Number of times to ping")
				return fs
			}(),
		},
		"setLogLevel": &command{
			f:           setLogLevel,
			description: "Set the logging level of the enclave",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("setLogLevel", flag.ExitOnError)
				fs.StringVar(&args.setLogLevel.level, "level", "INFO", "Log level to set")
				return fs
			}(),
		},
		"metrics": &command{
			f:           metrics,
			description: "Request metrics from --addr and print them as TSV",
			fs: func() *flag.FlagSet {
				fs := flag.NewFlagSet("metrics", flag.ExitOnError)
				fs.BoolVar(&args.metrics.updateEnvStats, "updateEnvStats", false, "Whether to request that environmental stats be updated prior to returning statistics")
				return fs
			}(),
		},
	}
)

func main() {
	for _, cmd := range commands {
		cmd.fs.StringVar(&args.addr, "addr", "", "Address (hostname:port) where control server is listening.  If empty string, will use the default port on the local machine's serving IP address")
	}
	var cmd *command
	var ok bool
	if len(os.Args) > 1 {
		cmd, ok = commands[os.Args[1]]
	}
	if !ok {
		log.Printf("First argument must be valid command.  Commands are:")
		for name, cmd := range commands {
			log.Printf("\t%q - %v", name, cmd.description)
		}
		os.Exit(1)
	}
	cmd.fs.Parse(os.Args[2:])
	if args.addr == "" {
		// Try to get address locally, by finding the preferred local address that routes remotely.
		conn, err := net.Dial("udp", "1.1.1.1:53")
		if err != nil {
			log.Fatal(err)
		}
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		args.addr = fmt.Sprintf("%v:8081", localAddr.IP)
		conn.Close()
	}
	log.Printf("Connecting to control server: %q", args.addr)
	cc := &client.ControlClient{Addr: args.addr}
	if err := cmd.f(cc); err != nil {
		log.Fatal(err)
	}
	log.Println("success")
}

func sendCommand(cc *client.ControlClient) error {
	req, err := commandRequest(args.command.filename)
	if err != nil {
		return fmt.Errorf("creating request body: %w", err)
	}

	resp, err := cc.Do(req)
	if err != nil {
		return fmt.Errorf("running request: %w", err)
	}
	fmt.Fprintln(os.Stderr, "successfully executed control request")
	fmt.Println(protojson.Format(resp))
	return nil
}

func commandRequest(filename string) (*pb.HostToEnclaveRequest, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file : %v", err)
	}

	request := &pb.HostToEnclaveRequest{}
	if args.command.binary {
		err = proto.Unmarshal(bs, request)
	} else {
		err = protojson.Unmarshal(bs, request)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto : %v", err)
	}
	return request, nil
}

var zeroID peerid.PeerID

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
	fmt.Printf("Raft state: %v\n", status.RaftState)
	fmt.Printf("\n")
loop:
	for _, peer := range status.Peers {
		pid, err := peerid.Make(peer.PeerId)
		if err != nil {
			return fmt.Errorf("invalid status peer ID %x: %v", peer.PeerId, err)
		}
		log.Printf("Peer %v (full ID %q)", pid, hex.EncodeToString(pid[:]))
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
		log.Printf("\tRole: %v", role)
		switch {
		case peer.Me:
		case peer.ConnectionStatus != nil:
			log.Printf("\tConnection status: %v", peer.ConnectionStatus.State)
			if peer.ConnectionStatus.State == pb.PeerState_PEER_DISCONNECTED {
				continue loop
			}
		}
		addr := "unknown"
		hostname := "unknown"
		if entry := peers[pid]; entry != nil {
			addr = entry.Addr
			if name, err := net.LookupAddr(strings.Split(addr, ":")[0]); err == nil && len(name) > 0 {
				hostname = name[0]
			}
		}
		log.Printf("\tAddress: %v (%v)", addr, hostname)
	}
	return nil
}

func relinquishLeadership(cc *client.ControlClient) error {
	_, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_RelinquishLeadership{RelinquishLeadership: true},
	})
	return err
}

func resetPeer(cc *client.ControlClient) error {
	if args.resetPeer.id == zeroID {
		return fmt.Errorf("must set ID (--id)")
	}
	_, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_ResetPeerId{ResetPeerId: args.resetPeer.id[:]},
	})
	return err
}

func connectPeer(cc *client.ControlClient) error {
	if args.connectPeer.id == zeroID {
		return fmt.Errorf("must set ID (--id)")
	}
	_, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_ConnectPeerId{ConnectPeerId: args.connectPeer.id[:]},
	})
	return err
}

func pingPeer(cc *client.ControlClient) error {
	if args.pingPeer.id == zeroID {
		return fmt.Errorf("must set ID (--id)")
	}
	for i := 0; i < args.pingPeer.count; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		start := time.Now()
		_, err := cc.Do(&pb.HostToEnclaveRequest{
			Inner: &pb.HostToEnclaveRequest_PingPeer{PingPeer: &pb.EnclavePeer{PeerId: args.pingPeer.id[:]}},
		})
		log.Printf("Ping from %q to %v finished in %v, err=%v", args.addr, args.pingPeer.id, time.Since(start), err)
	}
	return nil
}

func setLogLevel(cc *client.ControlClient) error {
	var (
		lvl int32
		ok  bool
	)
	// Be permissive in how we get the log level, allowing all of the following:
	//   * LOG_LEVEL_INFO
	//   * INFO
	//   * info
	if lvl, ok = pb.EnclaveLogLevel_value[strings.ToUpper(args.setLogLevel.level)]; ok {
	} else if lvl, ok = pb.EnclaveLogLevel_value["LOG_LEVEL_"+strings.ToUpper(args.setLogLevel.level)]; ok {
	} else {
		return fmt.Errorf("unknown log level %q", args.setLogLevel.level)
	}
	_, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_SetLogLevel{SetLogLevel: pb.EnclaveLogLevel(lvl)},
	})
	return err
}

func metrics(cc *client.ControlClient) error {
	resp, err := cc.Do(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_Metrics{Metrics: &pb.MetricsRequest{UpdateEnvStats: args.metrics.updateEnvStats}},
	})
	if err != nil {
		return fmt.Errorf("requesting metrics: %w", err)
	}
	got, ok := resp.Inner.(*pb.HostToEnclaveResponse_MetricsReply)
	if !ok {
		return fmt.Errorf("got non-metrics response: %T", resp.Inner)
	}
	// Sort our output so the ordering is returned consistently.
	out := []string{}
	for _, ctr := range got.MetricsReply.Counters {
		tags := []string{}
		for tagname, tagval := range ctr.Tags {
			tags = append(tags, fmt.Sprintf("%s:%s", tagname, tagval))
		}
		sort.Strings(tags)
		out = append(out, fmt.Sprintf("COUNT\t%v\t%v\t%d", ctr.Name, strings.Join(tags, ","), ctr.V))
	}
	for _, gauge := range got.MetricsReply.Counters {
		tags := []string{}
		for tagname, tagval := range gauge.Tags {
			tags = append(tags, fmt.Sprintf("%s:%s", tagname, tagval))
		}
		sort.Strings(tags)
		out = append(out, fmt.Sprintf("GAUGE\t%v\t%v\t%d", gauge.Name, strings.Join(tags, ","), gauge.V))
	}
	sort.Strings(out)
	fmt.Println("TYPE\tNAME\tTAGS\tVALUE")
	for _, s := range out {
		fmt.Println(s)
	}
	return nil
}
