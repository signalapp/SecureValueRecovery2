// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package client provides client implementations for SVR2Client endpoints
package client

import (
	"fmt"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

type SVR2Client struct {
	c       *websocket.Conn
	encrypt *noise.CipherState
	decrypt *noise.CipherState
	PubKey  []byte
}

func (sc *SVR2Client) Close() {
	sc.c.Close()
}

func (sc *SVR2Client) Send(req *pb.Request) (*pb.Response, error) {
	bs, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var ciphertext []byte
	if ciphertext, err = sc.encrypt.Encrypt(ciphertext, nil, bs); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err = sc.c.WriteMessage(websocket.BinaryMessage, ciphertext); err != nil {
		return nil, fmt.Errorf("writews: %w", err)
	}

	_, msg, err := sc.c.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("readws: %w", err)
	}

	var plaintext []byte
	if plaintext, err = sc.decrypt.Decrypt(plaintext, nil, msg); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var m pb.Response
	if err := proto.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &m, nil
}

func NewClient(c *websocket.Conn) (*SVR2Client, error) {
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
	return &SVR2Client{c, encrypt, decrypt, start.TestOnlyPubkey}, nil
}
