// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package dispatch

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/signalapp/svr2/config"
	pb "github.com/signalapp/svr2/proto"
	"github.com/signalapp/svr2/util"
)

type mockEnclave struct {
	ech chan *pb.EnclaveMessage   // messages from the 'enclave' to the dispatcher
	uch chan *pb.UntrustedMessage // messages from the host to the 'enclave'

	// can be used to delay requests arbitrarily
	requestIdx *atomic.Int32
	blocks     map[int32]chan struct{}
}

func (m *mockEnclave) SendMessage(p *pb.UntrustedMessage) error {
	index := m.requestIdx.Add(1) - 1
	if c, exists := m.blocks[index]; exists {
		<-c
	}
	m.uch <- p
	return nil
}

func (m *mockEnclave) close() {
	close(m.ech)
	close(m.uch)
}

type fixture struct {
	m *mockEnclave
	d *Dispatcher
}

type mockPeerSender struct{}

func (*mockPeerSender) Send(*pb.PeerMessage) error { return nil }

func makeFixture() fixture {
	return makeFixtureWithSender(&mockPeerSender{})
}

func makeFixtureWithSender(peerSender PeerSender) fixture {
	m := mockEnclave{
		make(chan *pb.EnclaveMessage),
		make(chan *pb.UntrustedMessage),
		&atomic.Int32{},
		make(map[int32]chan struct{}),
	}
	dispatcher := New(config.RaftHostConfig{
		TickDuration:       time.Second,
		EnclaveConcurrency: 3,
	}, &util.TxGenerator{}, &m, m.ech)
	go dispatcher.forwardToEnclaveLoop(context.Background())
	go dispatcher.forwardToHostLoop(context.Background(), peerSender)
	return fixture{&m, dispatcher}
}

func (f *fixture) Close() { f.m.close() }
func (f *fixture) hostSend(p *pb.UntrustedMessage) chan *pb.EnclaveMessage {
	recv := make(chan *pb.EnclaveMessage)
	go func() {
		defer close(recv)
		resp, _ := f.d.Send(p)
		recv <- resp
	}()
	// wait for the "enclave" to receive the request
	<-f.m.uch
	return recv
}
func (f *fixture) enclaveSend(p *pb.EnclaveMessage) {
	f.m.ech <- p
}

func TestRequestResponse(t *testing.T) {
	f := makeFixture()
	defer f.Close()

	// send a request and return a reply through the enclave
	recv := f.hostSend(untrustedReq(7))
	f.enclaveSend(enclaveReply(7))
	v, ok := (<-recv).Inner.(*pb.EnclaveMessage_H2EResponse)

	if !ok {
		t.Errorf("Send() received no response")
	}
	if v.H2EResponse.RequestId != 7 {
		t.Errorf("Send() response = %v, want %v", v.H2EResponse.RequestId, 7)
	}
}

func TestUnorderedResponses(t *testing.T) {
	f := makeFixture()
	defer f.Close()

	// send 2 requests
	recv1 := f.hostSend(untrustedReq(7))
	recv2 := f.hostSend(untrustedReq(8))

	// reply to second message
	f.enclaveSend(enclaveReply(8))

	select {
	case <-recv1:
		t.Errorf("Expected reply(8), got reply(7)")
	case r := <-recv2:
		v, ok := r.Inner.(*pb.EnclaveMessage_H2EResponse)
		if !ok {
			t.Errorf("Send() received no response")
		}
		if v.H2EResponse.RequestId != 8 {
			t.Errorf("Send() response = %v, want %v", v.H2EResponse.RequestId, 8)
		}
	}

	// reply to first message
	f.enclaveSend(enclaveReply(7))
	v, ok := (<-recv1).Inner.(*pb.EnclaveMessage_H2EResponse)

	if !ok {
		t.Errorf("Send() received no response")
	}
	if v.H2EResponse.RequestId != 7 {
		t.Errorf("Send() response = %v, want %v", v.H2EResponse.RequestId, 7)
	}
}

func TestNoReply(t *testing.T) {
	f := makeFixture()
	defer f.Close()
	recv1 := f.hostSend(untrustedCommand())
	resp := <-recv1
	if resp != nil {
		t.Errorf("Send() = %v, want = %v, send of reply should immediately finish", resp, nil)
	}
}

type slowPeerSender struct {
	block bool
	out   chan *pb.PeerMessage
}

func (s *slowPeerSender) Send(m *pb.PeerMessage) error {
	if s.block {
		return fmt.Errorf("bad thing")
	}
	s.out <- m
	return nil
}

func TestConcurrentRequests(t *testing.T) {
	f := makeFixture()
	defer f.Close()

	// block the first three enclave requests
	for i := int32(0); i < 3; i++ {
		f.m.blocks[i] = make(chan struct{})
	}

	finished := make(chan struct{}, 6)
	for i := 0; i < 6; i++ {
		go func() {
			f.d.Send(untrustedCommand())
			finished <- struct{}{}
		}()
	}
	if !channelEmpty(f.m.uch) {
		t.Fatal("expected no requests to make it to enclave")
	}

	// unblock 0 and 1
	f.m.blocks[0] <- struct{}{}
	f.m.blocks[1] <- struct{}{}

	// have 1 free permit, and all other requests are unblocked,
	// should be able to process all but requestId 2
	for i := 0; i < 5; i++ {
		<-f.m.uch
	}

	if !channelEmpty(f.m.uch) {
		t.Fatal("requestId 3 should be blocked")
	}
	f.m.blocks[2] <- struct{}{}
	<-f.m.uch

	for i := 0; i < 6; i++ {
		<-finished
	}

}

func channelEmpty[T any](ch chan T) bool {
	select {
	case <-ch:
		return false
	default:
		return true
	}
}

func untrustedReq(id uint64) *pb.UntrustedMessage {
	return &pb.UntrustedMessage{
		Inner: &pb.UntrustedMessage_H2ERequest{
			H2ERequest: &pb.HostToEnclaveRequest{
				RequestId: id,
			},
		},
	}
}

// doesn't require a response
func untrustedCommand() *pb.UntrustedMessage {
	return &pb.UntrustedMessage{Inner: &pb.UntrustedMessage_TimerTick{TimerTick: &pb.TimerTick{NewTimestampUnixSecs: uint64(time.Now().Unix())}}}
}

func enclaveReply(id uint64) *pb.EnclaveMessage {
	return &pb.EnclaveMessage{
		Inner: &pb.EnclaveMessage_H2EResponse{
			H2EResponse: &pb.HostToEnclaveResponse{
				RequestId: id,
				Inner:     &pb.HostToEnclaveResponse_Status{Status: pb.Error_OK},
			},
		},
	}
}
