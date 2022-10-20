// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/signalapp/svr2/peerid"
	pb "github.com/signalapp/svr2/proto"
)

/*
 * The host protocol supports only PeerConnectionMessages
 *
 * Each message is sent by first writing a varint length,
 * followed be the message contents
 */

func writeFramed(w io.Writer, m *pb.PeerConnectionMessage) error {
	bs, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	var frameBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(frameBuf[:], uint64(len(bs)))
	if _, err = w.Write(frameBuf[:n]); err != nil {
		return err
	}

	_, err = w.Write(bs)
	return err
}

func readFramed(r *bufio.Reader) (*pb.PeerConnectionMessage, error) {
	bs, err := readFramedRaw(r)
	if err != nil {
		return nil, err
	}
	var msg pb.PeerConnectionMessage
	if err := proto.Unmarshal(bs, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func readFramedRaw(r *bufio.Reader) ([]byte, error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if length > maxMessageLength {
		return nil, fmt.Errorf("message of length %v too long (or corrupt)", length)
	}

	dst := make([]byte, length)
	if _, err = io.ReadFull(r, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

func writeAck(w io.Writer, seqno sequenceNumber) error {
	return writeFramed(w, &pb.PeerConnectionMessage{
		Inner: &pb.PeerConnectionMessage_DataAck{
			DataAck: &pb.PeerConnectionDataAck{Seqno: seqno.proto()},
		},
	})
}

func readAck(r *bufio.Reader) (sequenceNumber, error) {
	msg, err := readFramed(r)
	if err != nil {
		return sequenceNumber{}, fmt.Errorf("readAck: %w", err)
	}
	in, ok := msg.Inner.(*pb.PeerConnectionMessage_DataAck)
	if !ok {
		return sequenceNumber{}, errors.New("readAck: unexpected peer connection message")
	}
	seqno, err := makeSeqno(in.DataAck.Seqno)
	if err != nil {
		return sequenceNumber{}, errors.New("readAck: no sequence number provided")
	}
	return seqno, nil
}

func writeHello(w io.Writer, from, to peerid.PeerID) error {
	return writeFramed(
		w,
		&pb.PeerConnectionMessage{
			Inner: &pb.PeerConnectionMessage_Hello{
				Hello: &pb.PeerConnectionHello{FromPeerId: from[:], ToPeerId: to[:]},
			},
		},
	)
}

func readHello(r *bufio.Reader) (from, to peerid.PeerID, returnedErr error) {
	msg, err := readFramed(r)
	if err != nil {
		returnedErr = fmt.Errorf("readHello: %w", err)
		return
	}
	in, ok := msg.Inner.(*pb.PeerConnectionMessage_Hello)
	if !ok {
		returnedErr = errors.New("hello: unexpected peer connection message")
		return
	}
	from, returnedErr = peerid.Make(in.Hello.FromPeerId)
	if returnedErr != nil {
		return
	}
	to, returnedErr = peerid.Make(in.Hello.ToPeerId)
	if returnedErr != nil {
		return
	}
	return
}

func writeHelloAck(w io.Writer, lastAck sequenceNumber) error {
	return writeFramed(
		w,
		&pb.PeerConnectionMessage{
			Inner: &pb.PeerConnectionMessage_HelloAck{
				HelloAck: &pb.PeerConnectionHelloAck{
					LastAck: lastAck.proto(),
				},
			},
		},
	)
}

func readHelloAck(r *bufio.Reader) (sequenceNumber, error) {
	var seqno sequenceNumber

	msg, err := readFramed(r)
	if err != nil {
		return seqno, fmt.Errorf("readHelloAck: %w", err)
	}
	in, ok := msg.Inner.(*pb.PeerConnectionMessage_HelloAck)
	if !ok {
		return seqno, errors.New("hello ack: unexpected peer connection message")
	}
	if seqno, err = makeSeqno(in.HelloAck.LastAck); err != nil {
		return seqno, err
	}
	return seqno, nil
}
