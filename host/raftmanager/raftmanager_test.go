// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package raftmanager

import (
	"context"
	"testing"

	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/peerid"
	pb "github.com/signalapp/svr2/proto"
)

type mockEnclave struct {
	msgs []*pb.HostToEnclaveRequest
}

func (t *mockEnclave) SendTransaction(p *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error) {
	t.msgs = append(t.msgs, p)
	return &pb.HostToEnclaveResponse{
		Inner: &pb.HostToEnclaveResponse_Status{
			Status: pb.Error_OK,
		},
	}, nil
}

type mockFinder peerid.PeerID

func (f mockFinder) FindRaftMember(ctx context.Context, me peerid.PeerID, addr string) (peerid.PeerID, error) {
	return peerid.PeerID(f), nil
}

func TestCreate(t *testing.T) {
	peer0 := [32]byte{byte(0)}
	mockEnclave := &mockEnclave{}

	raftManager := New(peer0, mockEnclave, mockFinder(peer0), config.Default())
	if err := raftManager.CreateOrJoin(context.Background()); err != nil {
		t.Error(err)
	}
	if len(mockEnclave.msgs) != 2 {
		t.Errorf("want %v enclave messages, got %v", 2, len(mockEnclave.msgs))
	}

	if mockEnclave.msgs[0].GetCreateNewRaftGroup() == false {
		t.Errorf("got message %v, want create request", mockEnclave.msgs[0])
	}
	if mockEnclave.msgs[1].GetRefreshAttestation() == nil {
		t.Errorf("got message %v, want refresh request", mockEnclave.msgs[1])
	}
}

func TestJoin(t *testing.T) {
	peer0 := [32]byte{byte(0)}
	peer1 := [32]byte{byte(1)}

	mockEnclave := &mockEnclave{}

	raftManager := New(peer0, mockEnclave, mockFinder(peer1), config.Default())
	if err := raftManager.CreateOrJoin(context.Background()); err != nil {
		t.Error(err)
	}
	if len(mockEnclave.msgs) != 2 {
		t.Errorf("want %v enclave messages, got %v", 2, len(mockEnclave.msgs))
	}

	if mockEnclave.msgs[0].GetJoinRaft() == nil {
		t.Errorf("got message %v, want create request", mockEnclave.msgs[0])
	}

	if mockEnclave.msgs[1].GetRefreshAttestation() == nil {
		t.Errorf("got message %v, want create request", mockEnclave.msgs[1])
	}
}
