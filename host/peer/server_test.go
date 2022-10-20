// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/signalapp/svr2/peerid"
	pb "github.com/signalapp/svr2/proto"
)

type mockEnclave struct {
	msgs []*pb.UntrustedMessage
}

func (t *mockEnclave) Send(p *pb.UntrustedMessage) (*pb.EnclaveMessage, error) {
	t.msgs = append(t.msgs, p)
	return nil, nil
}

type receiverFixture struct {
	enclave *mockEnclave
	pr      *PeerServer
	addr    string
	done    chan error
	ctx     context.Context
	cancel  context.CancelFunc
}

func (f *receiverFixture) close() error {
	f.cancel()
	return <-f.done
}

func (*receiverFixture) seq(i uint64) sequenceNumber {
	return sequenceNumber{epoch: 0, seq: i}
}

func startReceiver(t *testing.T) *receiverFixture {
	e := &mockEnclave{}

	ctx, cancel := context.WithCancel(context.Background())
	pr := NewPeerServer(ctx, peer(0), e)
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	done := make(chan error)
	go func() { done <- pr.Listen(ln) }()
	return &receiverFixture{
		e,
		pr,
		addr,
		done,
		ctx,
		cancel,
	}
}

func (f *receiverFixture) dial(t *testing.T) net.Conn {
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func (f *receiverFixture) handshake(t *testing.T, c net.Conn, initiatorId peerid.PeerID) sequenceNumber {
	reader := bufio.NewReader(c)
	if err := writeHello(c, initiatorId, f.pr.me); err != nil {
		t.Error(err)
	}
	ack, err := readHelloAck(reader)
	if err != nil {
		t.Error(err)
	}
	return ack
}

func (*receiverFixture) trySendAck(c net.Conn, data []byte, seqno sequenceNumber) error {
	if err := writeFramed(c, &pb.PeerConnectionMessage{
		Inner: &pb.PeerConnectionMessage_Data{
			Data: &pb.PeerConnectionData{
				Seqno: seqno.proto(),
				Msg: &pb.PeerMessage{
					Inner: &pb.PeerMessage_Syn{Syn: data},
				},
			},
		},
	}); err != nil {
		return err
	}

	ack, err := readAck(bufio.NewReader(c))
	if err != nil {
		return err
	}
	if ack != seqno {
		return fmt.Errorf("readAck()=%v, wanted %v", ack, seqno)
	}
	return nil
}

func (f *receiverFixture) sendAck(t *testing.T, c net.Conn, data []byte, seqno sequenceNumber) {
	if err := f.trySendAck(c, data, seqno); err != nil {
		t.Error(err)
	}
}

func TestSimpleAck(t *testing.T) {
	f := startReceiver(t)
	defer f.close()
	conn := f.dial(t)
	defer conn.Close()

	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	f.sendAck(t, conn, []byte("data"), f.seq(1))

	if len(f.enclave.msgs) != 1 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 1)
	}
	msg := f.enclave.msgs[0]
	if d, ok := msg.GetPeerMessage().Inner.(*pb.PeerMessage_Syn); !ok {
		t.Errorf("not syn")
	} else if !bytes.Equal(d.Syn, []byte("data")) {
		t.Errorf("got data %v, want %v", d.Syn, []byte("data"))
	}
}

func TestSequenceGap(t *testing.T) {
	f := startReceiver(t)
	defer f.close()
	conn := f.dial(t)
	defer conn.Close()

	if ack := f.handshake(t, conn, peer(1)); ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}
	f.sendAck(t, conn, []byte("data"), f.seq(1))
	if err := f.trySendAck(conn, []byte("data"), f.seq(3)); err == nil {
		t.Fatal("expected error sending ack")
	}
}
func TestEpochGap(t *testing.T) {
	f := startReceiver(t)
	defer f.close()
	conn := f.dial(t)
	defer conn.Close()

	if ack := f.handshake(t, conn, peer(1)); ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}
	f.sendAck(t, conn, []byte("data"), sequenceNumber{0, 1})
	f.sendAck(t, conn, []byte("data"), sequenceNumber{2, 0}) // skipping epoch is ok

	// skipping a message in epoch 3 is not ok
	if err := f.trySendAck(conn, []byte("data"), sequenceNumber{3, 1}); err == nil {
		t.Fatal("expected error sending ack")
	}
}

func TestEpochAck(t *testing.T) {
	f := startReceiver(t)
	defer f.close()
	conn := f.dial(t)
	defer conn.Close()

	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	f.sendAck(t, conn, []byte("data"), sequenceNumber{0, 1})
	f.sendAck(t, conn, []byte("data"), sequenceNumber{2, 0})
	f.sendAck(t, conn, []byte("data"), sequenceNumber{2, 1})
	f.sendAck(t, conn, []byte("data"), sequenceNumber{3, 0})

	if len(f.enclave.msgs) != 4 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 4)
	}
}

func TestDisconnectAck(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	conn := f.dial(t)
	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	f.sendAck(t, conn, []byte("data"), f.seq(1))
	f.sendAck(t, conn, []byte("data1"), f.seq(2))
	f.sendAck(t, conn, []byte("data2"), f.seq(3))
	if len(f.enclave.msgs) != 3 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 3)
	}

	conn.Close()
	conn = f.dial(t)
	ack = f.handshake(t, conn, peer(1))
	if ack != f.seq(3) {
		t.Errorf("handshake ack = %v, want %v", ack, 3)
	}
	f.sendAck(t, conn, []byte("data4"), f.seq(4))
	if len(f.enclave.msgs) != 4 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 4)
	}
}

func TestDisconnectEpochAck(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	conn := f.dial(t)
	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	f.sendAck(t, conn, []byte("data"), sequenceNumber{5, 0})
	if len(f.enclave.msgs) != 1 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 3)
	}

	conn.Close()
	conn = f.dial(t)
	if ack = f.handshake(t, conn, peer(1)); ack != (sequenceNumber{5, 0}) {
		t.Errorf("handshake ack = %v, want %v", ack, "5:0")
	}
	f.sendAck(t, conn, []byte("data4"), sequenceNumber{5, 1})
	if len(f.enclave.msgs) != 2 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 2)
	}
}

func TestResend(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	conn := f.dial(t)
	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	f.sendAck(t, conn, []byte("data"), f.seq(1))
	f.sendAck(t, conn, []byte("data"), f.seq(1))
}

func TestReconnectingClient(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	conn := f.dial(t)
	ack := f.handshake(t, conn, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	// reconnect, server should disconnect old connection
	conn2 := f.dial(t)
	ack = f.handshake(t, conn2, peer(1))
	if ack != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack, 0)
	}

	bs := []byte{0}
	_, err := conn.Read(bs)
	if err == nil {
		t.Error("expected disconnect for original client")
	}
}

func TestMultiplePeers(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	conn1 := f.dial(t)
	ack1 := f.handshake(t, conn1, peer(1))
	if ack1 != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack1, 0)
	}

	conn2 := f.dial(t)
	ack2 := f.handshake(t, conn2, peer(2))
	if ack2 != (sequenceNumber{}) {
		t.Errorf("handshake ack = %v, want %v", ack2, 0)
	}

	f.sendAck(t, conn1, []byte("data1"), f.seq(1))
	f.sendAck(t, conn2, []byte("data2"), f.seq(1))

	if len(f.enclave.msgs) != 2 {
		t.Errorf("got %v forwarded messages, want %v", len(f.enclave.msgs), 2)
	}
	got1 := f.enclave.msgs[0].GetPeerMessage().Inner.(*pb.PeerMessage_Syn).Syn
	got2 := f.enclave.msgs[1].GetPeerMessage().Inner.(*pb.PeerMessage_Syn).Syn

	if !bytes.Equal(got1, []byte("data1")) {
		t.Errorf("got data %v, want %v", got1, []byte("data1"))
	}

	if !bytes.Equal(got2, []byte("data2")) {
		t.Errorf("got data %v, want %v", got2, []byte("data2"))
	}

}

func TestEndToEnd(t *testing.T) {
	f := startReceiver(t)
	defer f.close()

	sender := createSender(withLookup(serverID, f.addr))
	done := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- sender.run(ctx) }()

	msg := pb.PeerMessage{
		PeerId: f.pr.me[:],
		Inner:  &pb.PeerMessage_Syn{Syn: []byte("data")},
	}

	*sender.tx.Load() <- &msg
	cancel()
	<-done
}

func TestRejectsNotMyPeerID(t *testing.T) {
	f := startReceiver(t)
	defer f.close()
	conn := f.dial(t)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if err := writeHello(conn, peer(1), peer(12 /*not me*/)); err != nil {
		t.Error(err)
	}
	if _, err := readHelloAck(reader); err == nil {
		t.Fatal("accepted connection when toPeerID did not match server")
	}
}
