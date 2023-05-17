// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

func vSock(port, cid int, simulated bool) (_ net.Conn, returnedErr error) {
	if simulated {
		return net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	return vsock.Dial(uint32(cid), uint32(port), nil)
}

type Nitro struct {
	c   chan *pb.EnclaveMessage
	pid peerid.PeerID

	wMu  sync.Mutex
	sock net.Conn

	msgIDGen uint64
	callMu   sync.Mutex
	calls    map[uint64]chan<- error
}

var testNitroIface Enclave = (*Nitro)(nil)

func (n *Nitro) send(pb proto.Message) error {
	buf, err := proto.Marshal(pb)
	if err != nil {
		return fmt.Errorf("marshaling proto: %w", err)
	}
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(buf)))

	n.wMu.Lock()
	defer n.wMu.Unlock()
	if _, err := n.sock.Write(sizeBuf[:]); err != nil {
		return fmt.Errorf("writing size: %w", err)
	} else if _, err := n.sock.Write(buf); err != nil {
		return fmt.Errorf("writing proto: %v", err)
	}
	return nil
}

func (n *Nitro) recv(pb proto.Message) error {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(n.sock, sizeBuf[:]); err != nil {
		return fmt.Errorf("reading size: %w", err)
	}
	size := binary.BigEndian.Uint32(sizeBuf[:])
	buf := make([]byte, size)
	if _, err := io.ReadFull(n.sock, buf); err != nil {
		return fmt.Errorf("reading proto: %w", err)
	} else if err := proto.Unmarshal(buf, pb); err != nil {
		return fmt.Errorf("unmarshaling proto: %w", err)
	}
	return nil
}

func NewNitro(config *pb.InitConfig, port, cid int) (_ *Nitro, returnedErr error) {
	sock, err := vSock(port, cid, config.GroupConfig.Simulated)
	if err != nil {
		return nil, fmt.Errorf("creating nitro socket: %w", err)
	}
	if _, err := sock.Write([]byte{'N'}); err != nil {
		return nil, fmt.Errorf("writing nitro hello byte: %w", err)
	}
	n := &Nitro{
		c:     make(chan *pb.EnclaveMessage, 100),
		sock:  sock,
		calls: map[uint64]chan<- error{},
	}
	defer func() {
		if returnedErr != nil {
			n.Close()
		}
	}()
	config.InitialTimestampUnixSecs = uint64(time.Now().Unix())
	initReq := &pb.InboundMessage{
		Inner: &pb.InboundMessage_Init{Init: config},
	}
	if err := n.send(initReq); err != nil {
		return nil, err
	}
	var initResp pb.OutboundMessage
	if err := n.recv(&initResp); err != nil {
		return nil, fmt.Errorf("init recv: %w", err)
	} else if inner, ok := initResp.Inner.(*pb.OutboundMessage_Init); !ok {
		return nil, fmt.Errorf("init response was not type InitCallResponse")
	} else if n.pid, err = peerid.Make(inner.Init.PeerId); err != nil {
		return nil, fmt.Errorf("init received peerid: %w", err)
	}
	go n.readOutputs()
	return n, nil
}

func (n *Nitro) readNextOutput() error {
	var out pb.OutboundMessage
	if err := n.recv(&out); err != nil {
		return fmt.Errorf("recv error: %w", err)
	}
	switch v := out.Inner.(type) {
	case *pb.OutboundMessage_Init:
		return fmt.Errorf("received init")
	case *pb.OutboundMessage_Msg:
		if err := n.receivedResponse(v.Msg); err != nil {
			return fmt.Errorf("received response error: %w", err)
		}
	case *pb.OutboundMessage_Out:
		var emsg pb.EnclaveMessage
		if err := proto.Unmarshal(v.Out, &emsg); err != nil {
			return fmt.Errorf("unmarshal of EnclaveMessage: %w", err)
		}
		n.c <- &emsg
	default:
		return fmt.Errorf("unexpected inner type %T", out.Inner)
	}
	return nil
}

func (n *Nitro) receivedResponse(m *pb.MsgCallResponse) error {
	n.callMu.Lock()
	defer n.callMu.Unlock()
	done := n.calls[m.Id]
	if done == nil {
		return fmt.Errorf("received response to msg %d which isn't an active call", m.Id)
	}
	delete(n.calls, m.Id)
	if m.Status != pb.Error_OK {
		done <- m.Status // should not block, since done is a buffered channel
	} else {
		done <- nil
	}
	return nil
}

func (n *Nitro) readOutputs() {
	var err error
	for err == nil {
		err = n.readNextOutput()
	}
	log.Printf("nitro readOutputs failure: %v", err)
	n.Close()
	close(n.c)
}

func (n *Nitro) PID() peerid.PeerID {
	return n.pid
}

func (n *Nitro) OutputMessages() <-chan *pb.EnclaveMessage {
	return n.c
}

func (n *Nitro) SendMessage(msgPB *pb.UntrustedMessage) error {
	buf, err := proto.Marshal(msgPB)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	id := atomic.AddUint64(&n.msgIDGen, 1)
	in := pb.InboundMessage{
		Inner: &pb.InboundMessage_Msg{
			Msg: &pb.MsgCallRequest{
				Id:   id,
				Data: buf,
			},
		},
	}
	done := make(chan error, 1)
	n.callMu.Lock()
	n.calls[id] = done
	n.callMu.Unlock()
	if err := n.send(&in); err != nil {
		n.callMu.Lock()
		delete(n.calls, id)
		n.callMu.Unlock()
		n.Close() // a failure to send is a permanent failure
		return fmt.Errorf("sending: %w", err)
	}
	return <-done
}

func (n *Nitro) Close() {
	logger.Errorf("Closing Nitro")
	n.sock.Close()
}
