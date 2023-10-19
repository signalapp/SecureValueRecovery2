// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/servicetest"

	pb "github.com/signalapp/svr2/proto"
)

// mapPeerDB is a static mapping of peers initialized at startup
type mapPeerDB struct {
	m map[peerid.PeerID]string
}

type testResetter map[peerid.PeerID]bool

func (t testResetter) ResetPeer(peerID peerid.PeerID) error {
	log.Printf("Resetting peer %v", peerID)
	t[peerID] = true
	return nil
}

// Implements PeerLookup
func (m *mapPeerDB) Lookup(ctx context.Context, peer peerid.PeerID) (*string, error) {
	val, ok := m.m[peer]
	if !ok {
		return nil, nil
	}
	return &val, nil
}

type clientFixture struct {
	data   []byte
	r      *bufio.Reader
	server net.Conn
	client net.Conn
	done   chan error
}

// start initializers a server/client connection, provides it to the sender,
// and allows subsequent calls to receive messages from the server connection
func (c *clientFixture) start(t *testing.T, sender *peerSender) {
	c.startFrom(t, sender, sequenceNumber{})
}

func (c *clientFixture) startFrom(t *testing.T, sender *peerSender, helloAck sequenceNumber) {
	c.server, c.client = net.Pipe()
	c.r = bufio.NewReader(c.server)

	c.done = make(chan error)
	go func() { c.done <- sender.handleConnection(context.Background(), c.client) }()

	if from, to := c.readHello(t); from != clientID {
		t.Errorf("client hello fromPeerID %v, want %v", from, clientID)
	} else if to != serverID {
		t.Errorf("client hello toPeerID %v, want %v", to, serverID)
	}

	f.writeHelloAck(t, helloAck)
}

func (c *clientFixture) close() error {
	c.server.Close()
	return <-c.done
}

func (c *clientFixture) readHello(t *testing.T) (to, from peerid.PeerID) {
	from, to, err := readHello(c.r)
	if err != nil {
		t.Fatalf("fReadHello: %v", err)
	}
	return from, to
}

func (c *clientFixture) writeHelloAck(t *testing.T, seqno sequenceNumber) {
	if err := writeHelloAck(c.server, seqno); err != nil {
		t.Error(err)
	}
}

func (c *clientFixture) writeAck(t *testing.T, seqno sequenceNumber) {
	if err := writeAck(c.server, seqno); err != nil {
		t.Error(err)
	}
}

func (c *clientFixture) sendSyn(t *testing.T, s *peerSender) {
	c.queueMessage(t, s, c.peerSynMessage())
}

func (c *clientFixture) sendData(t *testing.T, s *peerSender) {
	c.queueMessage(t, s, c.peerDataMessage())
}

func (c *clientFixture) queueMessage(t *testing.T, s *peerSender, msg *pb.PeerMessage) {
	if !s.queueMessage(msg) {
		t.Fatalf("unable to queue message")
	}
}

func (c *clientFixture) expectMessage(t *testing.T, expectedSeqno sequenceNumber) {
	m, err := readFramed(c.r)
	if err != nil {
		t.Error(err)
		return
	}
	actual, err := makeSeqno(m.GetData().Seqno)
	if err != nil {
		t.Error(err)
		return
	}
	if actual != expectedSeqno {
		t.Errorf("message seqno=%v, want %v", actual, expectedSeqno)
		return
	}
	var bs []byte
	switch v := m.GetData().GetMsg().Inner.(type) {
	case *pb.PeerMessage_Syn:
		bs = v.Syn
	case *pb.PeerMessage_Data:
		bs = v.Data
	default:
		t.Errorf("unexpected message")
		return
	}
	if !bytes.Equal(bs, c.data) {
		t.Errorf("message data=%v, want %v", bs, c.data)
	}
}

func (c *clientFixture) sequenced(seqno sequenceNumber) *pb.PeerConnectionData {
	return &pb.PeerConnectionData{
		Msg: &pb.PeerMessage{
			Inner: &pb.PeerMessage_Syn{Syn: c.data},
		},
		Seqno: seqno.proto(),
	}
}

func (c *clientFixture) peerSynMessage() *pb.PeerMessage {
	return &pb.PeerMessage{
		Inner:  &pb.PeerMessage_Syn{Syn: c.data},
		PeerId: serverID[:],
	}
}

func (c *clientFixture) peerDataMessage() *pb.PeerMessage {
	return &pb.PeerMessage{
		Inner:  &pb.PeerMessage_Data{Data: c.data},
		PeerId: serverID[:],
	}
}

type SenderOption func(*peerSender)

func withBuffer(bufSize int) SenderOption {
	return func(sender *peerSender) {
		sender.cfg.BufferSize = bufSize
		c := make(chan *pb.PeerMessage, bufSize)
		sender.tx.Store(&c)
	}
}

func withLookup(peerID peerid.PeerID, addr string) SenderOption {
	return func(sender *peerSender) {
		sender.peerLookup = &mapPeerDB{map[peerid.PeerID]string{peerID: addr}}
	}
}

func createSender(options ...SenderOption) *peerSender {
	cfg := config.Default()
	sender := newPeerSender(clientID, serverID, &mapPeerDB{}, &cfg.Peer)
	for _, opt := range options {
		opt(sender)
	}
	return sender
}

var (
	clientID = peer(0)
	serverID = peer(1)
	f        = clientFixture{data: []byte("data")}
)

func (*clientFixture) seq(s uint64) sequenceNumber {
	return sequenceNumber{
		seq:   s,
		epoch: 0,
	}
}

func TestProcessAck(t *testing.T) {

	orig := []*pb.PeerConnectionData{
		f.sequenced(f.seq(1)),
		f.sequenced(f.seq(2)),
		f.sequenced(f.seq(3)),
	}

	tests := []struct {
		ack      sequenceNumber
		expected []*pb.PeerConnectionData
	}{
		{f.seq(0), orig},
		{f.seq(1), orig[1:]},
		{f.seq(2), orig[2:]},
		{f.seq(3), []*pb.PeerConnectionData{}},
		// acks past max sent, should drop everything
		{f.seq(4), []*pb.PeerConnectionData{}},
		{f.seq(100), []*pb.PeerConnectionData{}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("ack=%v", tt.ack), func(t *testing.T) {
			sender := peerSender{pending: orig}
			err := sender.processAck(tt.ack)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(sender.pending, tt.expected) {
				t.Errorf("processAck(%v)=%v, want %v", tt.ack, sender.pending, tt.expected)
			}
		})
	}
}

func TestHandleConnection(t *testing.T) {
	sender := createSender()

	f.start(t, sender)
	f.sendSyn(t, sender)
	f.expectMessage(t, sequenceNumber{1, 0})
	if sender.lastAck != (sequenceNumber{}) {
		t.Errorf("sender lastAck=%v, want %v", sender.lastAck, 0)
	}

	f.writeAck(t, sequenceNumber{1, 0})
	f.close()

	if sender.lastAck != (sequenceNumber{1, 0}) {
		t.Errorf("sender lastAck=%v, want %v", sender.lastAck, 1)
	}
}

func TestResendPending(t *testing.T) {
	for _, i := range []uint64{3, 4, 5, 8, 9} {
		t.Run(fmt.Sprintf("helloAck%v", i), func(t *testing.T) {
			f.resendPendingHelper(t, f.seq(i))
		})
	}
}

func (c *clientFixture) resendPendingHelper(t *testing.T, helloAck sequenceNumber) {
	sender := createSender()

	f.start(t, sender)

	for i := 1; i < 10; i++ {
		f.sendData(t, sender)
		f.expectMessage(t, f.seq(uint64(i)))
	}

	// lie and only ack id 3
	f.writeAck(t, f.seq(3))
	t.Logf("done reason: %v", f.close())

	// restart, should resend from helloAck up to 10
	f.startFrom(t, sender, helloAck)

	for i := helloAck.seq + 1; i < 10; i++ {
		f.expectMessage(t, f.seq(i))
	}

	// should be able to send a new message at seqno=10
	f.sendData(t, sender)
	f.expectMessage(t, f.seq(10))

	t.Logf("done reason: %v", f.close())
}

func TestDropOldEpoch(t *testing.T) {
	sender := createSender()

	f.start(t, sender)

	// these should not be resent on disconnect
	f.sendSyn(t, sender)
	f.expectMessage(t, sequenceNumber{epoch: 1, seq: 0})
	f.sendData(t, sender)
	f.expectMessage(t, sequenceNumber{epoch: 1, seq: 1})

	// SYN should start a new epoch
	f.sendSyn(t, sender)
	f.expectMessage(t, sequenceNumber{epoch: 2, seq: 0})
	f.sendData(t, sender)
	f.expectMessage(t, sequenceNumber{epoch: 2, seq: 1})

	// should resend the Syn and first message
	t.Logf("done reason: %v", f.close())
	f.startFrom(t, sender, sequenceNumber{0, 1})
	f.expectMessage(t, sequenceNumber{epoch: 2, seq: 0})
	f.expectMessage(t, sequenceNumber{epoch: 2, seq: 1})

	t.Logf("done reason: %v", f.close())

}

func TestManySyncs(t *testing.T) {
	sender := createSender()

	f.start(t, sender)

	// these should not be resent on disconnect
	for i := uint32(1); i <= 5; i++ {
		f.sendSyn(t, sender)
		f.expectMessage(t, sequenceNumber{epoch: i, seq: 0})
	}

	// should only send the latest epoch
	t.Logf("done reason: %v", f.close())
	f.startFrom(t, sender, sequenceNumber{0, 1})
	f.expectMessage(t, sequenceNumber{epoch: 5, seq: 0})
	t.Logf("done reason: %v", f.close())

}

func TestBufferLimit(t *testing.T) {
	sender := createSender(withBuffer(10))

	f.start(t, sender)

	// first 10 sends should be fine
	for i := 0; i < 10; i++ {
		f.sendData(t, sender)
	}

	// 11th send we're out of space
	if sender.queueMessage(f.peerDataMessage()) {
		t.Fatalf("want error from queue message, but was successful")
	}

	// send a Syn, which should work and free up our buffer for 10 more sends
	f.sendSyn(t, sender)
	for i := 0; i < 9; i++ {
		f.sendData(t, sender)
	}
}

func TestAbandonPeer(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	lookup := &mapPeerDB{map[peerid.PeerID]string{serverID: ln.Addr().String()}}

	// no longer listening on address
	ln.Close()
	resetter := testResetter{}

	peerClient := NewPeerClient(context.Background(), clientID, lookup, &config.PeerConfig{
		AbandonDuration: time.Millisecond * 10,
		BufferSize:      1000,
	}, resetter)

	// eventually these should fail
	for i := 0; i < 10; i++ {
		err = peerClient.Send(&pb.PeerMessage{
			PeerId: serverID[:],
			Inner:  &pb.PeerMessage_Data{},
		})
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond * 5)
	}

	if !reflect.DeepEqual(resetter, testResetter{serverID: true}) {
		t.Fatalf("didn't reset server ID: %+v %+v", resetter, serverID)
	}

	if _, ok := peerClient.abandonedPeers[serverID]; !ok {
		t.Fatal("peer should be marked abandoned")
	}

}

func TestAbandonZombiePeer(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	lookup := &mapPeerDB{map[peerid.PeerID]string{serverID: ln.Addr().String()}}

	resetter := testResetter{}
	peerClient := NewPeerClient(context.Background(), clientID, lookup, &config.PeerConfig{
		AbandonDuration: time.Millisecond * 10,
		BufferSize:      1000,
	}, resetter)

	// server accepts a connection and reads a hello, but then terminates
	serverDone := make(chan error, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(serverDone)
				return
			}
			r := bufio.NewReader(c)
			if _, _, err = readHello(r); err != nil {
				serverDone <- err
				return
			}
			c.Close()
		}
	}()

	// eventually these should fail
	for i := 0; i < 10; i++ {
		err = peerClient.Send(&pb.PeerMessage{
			PeerId: serverID[:],
			Inner:  &pb.PeerMessage_Data{},
		})
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond * 5)
	}

	if !reflect.DeepEqual(resetter, testResetter{serverID: true}) {
		t.Fatalf("didn't reset server ID: %+v %+v", resetter, serverID)
	}

	if _, ok := peerClient.abandonedPeers[serverID]; !ok {
		t.Fatal("peer should be marked abandoned")
	}
	ln.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

}

func TestProdigalPeer(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	lookup := &mapPeerDB{map[peerid.PeerID]string{serverID: ln.Addr().String()}}
	resetter := testResetter{}
	peerClient := NewPeerClient(context.Background(), clientID, lookup, &config.PeerConfig{
		AbandonDuration: time.Minute,
		BufferSize:      1,
	}, resetter)

	peerClient.abandonedPeers[serverID] = true

	dataMsg := &pb.PeerMessage{
		PeerId: serverID[:],
		Inner:  &pb.PeerMessage_Data{},
	}

	// a data message should be outright rejected
	if err := peerClient.Send(dataMsg); err == nil {
		t.Fatalf("Send(data message) = nil")
	} else if !reflect.DeepEqual(resetter, testResetter{serverID: true}) {
		t.Fatalf("Send(data message) didn't reset serverID: %v %v", resetter, serverID)
	}
	delete(resetter, serverID)

	serverDone := make(chan error, 1)
	server := errorServer{seqno: sequenceNumber{1, 9}, id: serverID, ln: ln}
	go func() { serverDone <- server.run(fsOk, 1) }()

	// should allow an RST message
	rstMsg := &pb.PeerMessage{
		PeerId: serverID[:],
		Inner:  &pb.PeerMessage_Rst{Rst: true},
	}
	if err = peerClient.Send(rstMsg); err != nil {
		t.Fatalf("Send(rst) = %v, want %v", err, nil)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server failed with: %v", err)
	}

	if expected := (sequenceNumber{1, 10}); server.seqno != expected {
		t.Fatalf("server recieved seqno=%v, want %v", server.seqno, expected)
	}
	if len(resetter) != 0 {
		t.Fatalf("server reset after it should have: %v", resetter)
	}
}

func TestPeerLookupFails(t *testing.T) {
	// peer won't be found
	lookup := &mapPeerDB{map[peerid.PeerID]string{}}

	dataMsg := &pb.PeerMessage{
		PeerId: serverID[:],
		Inner:  &pb.PeerMessage_Data{},
	}

	peerClient := NewPeerClient(context.Background(), clientID, lookup, &config.PeerConfig{
		AbandonDuration: time.Minute,
		BufferSize:      1000,
	}, testResetter{})

	if err := peerClient.Send(dataMsg); err != nil {
		t.Fatalf("first send failed: %v", err)
	}
	_, err := servicetest.RetryFun(time.Second*5, func() (interface{}, error) {
		err := peerClient.Send(dataMsg)
		if errors.Is(err, errAbandonPeer) {
			return nil, errors.New("should eventually fail")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal("send never failed")
	}

}

func TestRetryErrors(t *testing.T) {

	tests := []struct {
		name string
		// where to error on first server run
		fs failureStage
		// number of messages to read on first server run
		expectedFirstRun int
		// number of messages to read on second server run
		expectedSecondRun int
	}{
		{"hello", fsHello, 0, 2},
		{"helloAck", fsHelloAck, 0, 2},
		{"receive", fsReceive, 0, 2},
		{"ack", fsAck, 2, 0},
		{"ok", fsOk, 2, 0},
		{"ok split", fsOk, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatal(err)
			}
			errorServer := errorServer{id: serverID, ln: ln}
			serverDone := make(chan error)
			go func() {
				// run error server, erroring when configured
				if err := errorServer.run(tt.fs, tt.expectedFirstRun); err != nil {
					log.Println(err)
					t.Error(err)
				}

				t.Logf("finished first run")

				// restart errorServer but always succeed
				err := errorServer.run(fsOk, tt.expectedSecondRun)
				ln.Close()
				serverDone <- err
			}()

			// send two messages to the error server
			sender := createSender(
				withLookup(serverID, ln.Addr().String()),
				withBuffer(2))

			senderDone := make(chan error)
			ctx, cancel := context.WithCancel(context.Background())
			go func() { senderDone <- sender.run(ctx) }()
			f.sendSyn(t, sender)
			f.sendData(t, sender)

			// wait for server to read our messages
			select {
			case err := <-senderDone:
				t.Fatal(err)
			case err := <-serverDone:
				if err != nil {
					t.Error(err)
				}
			}
			cancel()
			t.Logf("finished %v", <-senderDone)
		})
	}

}

type failureStage = int

const (
	fsHello failureStage = iota
	fsHelloAck
	fsReceive
	fsAck
	fsOk
)

type errorServer struct {
	seqno sequenceNumber
	id    peerid.PeerID
	ln    net.Listener
}

func (e *errorServer) run(failure failureStage, expectedMessages int) error {
	c, err := e.ln.Accept()
	if err != nil {
		return err
	}
	log.Printf("got connection local=%v, remote=%v", c.LocalAddr().String(), c.RemoteAddr().String())

	defer c.Close()

	r := bufio.NewReader(c)

	if failure == fsHello {
		return nil
	}

	if _, _, err = readHello(r); err != nil {
		return err
	}

	if failure == fsHelloAck {
		return nil
	}

	if err := writeHelloAck(c, e.seqno); err != nil {
		return err
	}

	if failure == fsReceive {
		return nil
	}

	// receive expectedMessages messages
	for i := 0; i < expectedMessages; i++ {
		msg, err := readFramed(r)
		if err != nil {
			return err
		}
		e.seqno, err = makeSeqno(msg.GetData().Seqno)
		if err != nil {
			return err
		}

	}

	if failure == fsAck {
		return nil
	}

	if err := writeAck(c, e.seqno); err != nil {
		return err
	}
	return nil
}

func peer(i byte) peerid.PeerID {
	return [32]byte{i}
}
