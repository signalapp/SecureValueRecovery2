// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"testing"
	"time"

	pb "github.com/signalapp/svr2/proto"
)

var (
	validConfig = pb.InitConfig{
		EnclaveConfig: &pb.EnclaveConfig{
			Raft: &pb.RaftConfig{
				ElectionTicks:                 30,
				HeartbeatTicks:                15,
				ReplicationChunkBytes:         1 << 20,
				ReplicaVotingTimeoutTicks:     120,
				ReplicaMembershipTimeoutTicks: 240,
				LogMaxBytes:                   10 << 20,
			},
			E2ETxnTimeoutTicks: 30,
		},
		GroupConfig: &pb.RaftGroupConfig{
			DbVersion:          pb.DatabaseVersion_DATABASE_VERSION_SVR2,
			MinVotingReplicas:  1,
			MaxVotingReplicas:  5,
			AttestationTimeout: 3600,
			Simulated:          true,
		},
	}
)

func TestSimulatedEnclave(t *testing.T) {
	sgx := SGXEnclave()
	if err := sgx.Init("../../enclave/build/enclave.test", &validConfig); err != nil {
		t.Fatal(err)
	}
	c := sgx.OutputMessages()
	// Create and close a client.
	if err := sgx.SendMessage(&pb.UntrustedMessage{
		Inner: &pb.UntrustedMessage_H2ERequest{
			H2ERequest: &pb.HostToEnclaveRequest{
				RequestId: 1,
				Inner: &pb.HostToEnclaveRequest_NewClient{
					NewClient: &pb.NewClientRequest{},
				},
			},
		},
	}); err != nil {
		t.Fatalf("sending new client request: %v", err)
	}
	var clientID uint64
	select {
	case msg := <-c:
		if m, ok := msg.Inner.(*pb.EnclaveMessage_H2EResponse); !ok {
			t.Fatalf("not EnclaveMessage_H2EResponse: %v", msg)
		} else if nc, ok := m.H2EResponse.Inner.(*pb.HostToEnclaveResponse_NewClientReply); !ok {
			t.Fatalf("not HostToEnclaveResponse_NewClientReply: %v", msg)
		} else {
			clientID = nc.NewClientReply.ClientId
		}
	case <-time.After(time.Second * 5):
		t.Fatal("took >5s to get response")
	}
	if err := sgx.SendMessage(&pb.UntrustedMessage{
		Inner: &pb.UntrustedMessage_H2ERequest{
			H2ERequest: &pb.HostToEnclaveRequest{
				RequestId: 2,
				Inner: &pb.HostToEnclaveRequest_CloseClient{
					CloseClient: &pb.CloseClientRequest{
						ClientId: clientID,
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("sending client close: %v", err)
	}
	select {
	case msg := <-c:
		if m, ok := msg.Inner.(*pb.EnclaveMessage_H2EResponse); !ok {
			t.Fatalf("not EnclaveMessage_H2EResponse: %v", msg)
		} else if s, ok := m.H2EResponse.Inner.(*pb.HostToEnclaveResponse_Status); !ok {
			t.Fatalf("not HostToEnclaveResponse_NewClientReply: %v", msg)
		} else if s.Status != pb.Error_OK {
			t.Fatalf("close status, want %v got %v", pb.Error_OK, s.Status)
		}
	case <-time.After(time.Second * 5):
		t.Fatal("took >5s to get response")
	}

	go sgx.Close()
	// Make sure that Close() actually closes the output channel.
	<-c
}
