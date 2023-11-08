// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package client provides client implementations for SVRClient endpoints
package client

import (
	"fmt"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

type SVRClient struct {
	c       *websocket.Conn
	encrypt *noise.CipherState
	decrypt *noise.CipherState
	PubKey  []byte
}

func (sc *SVRClient) Close() {
	sc.c.Close()
}

func (sc *SVRClient) send(req, resp proto.Message) error {
	bs, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var ciphertext []byte
	if ciphertext, err = sc.encrypt.Encrypt(ciphertext, nil, bs); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err = sc.c.WriteMessage(websocket.BinaryMessage, ciphertext); err != nil {
		return fmt.Errorf("writews: %w", err)
	}

	_, msg, err := sc.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("readws: %w", err)
	}

	var plaintext []byte
	if plaintext, err = sc.decrypt.Decrypt(plaintext, nil, msg); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := proto.Unmarshal(plaintext, resp); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

func (sc *SVRClient) Send2(req *pb.Request) (*pb.Response, error) {
	var resp pb.Response
	return &resp, sc.send(req, &resp)
}

func (sc *SVRClient) Send3(req *pb.Request3) (*pb.Response3, error) {
	var resp pb.Response3
	return &resp, sc.send(req, &resp)
}

func NewClient(c *websocket.Conn) (*SVRClient, error) {
	// extract the server public key
	_, msg, err := c.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("readws: %w", err)
	}

	var start pb.ClientHandshakeStart
	if err := proto.Unmarshal(msg, &start); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// start a noise handshake
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  start.TestOnlyPubkey,
	})
	if err != nil {
		return nil, fmt.Errorf("hanshake init: %w", err)
	}
	var out []byte
	out, _, _, err = hs.WriteMessage(out, nil)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	if err = c.WriteMessage(websocket.BinaryMessage, out); err != nil {
		return nil, fmt.Errorf("writews: %w", err)
	}

	if _, msg, err = c.ReadMessage(); err != nil {
		return nil, fmt.Errorf("handshake readws: %w", err)
	}

	_, encrypt, decrypt, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, fmt.Errorf("handshake read: %w", err)
	}
	return &SVRClient{c, encrypt, decrypt, start.TestOnlyPubkey}, nil
}
