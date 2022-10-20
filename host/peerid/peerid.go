// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package peerid provides the PeerID type. Enclaves identify remote peers by
// their PeerID, which is a a 256 bit public key that an enclave generates at startup.
// Hosts are responsible for mapping PeerIDs to the actual remote endpoints used for
// network communication.
package peerid

import (
	"encoding/hex"
	"fmt"
)

type PeerID [32]byte

func Make(s []byte) (PeerID, error) {
	if len(s) != 32 {
		return PeerID{}, fmt.Errorf("incorrect peer id length %v", len(s))
	}
	var out PeerID
	copy(out[:], s)
	return out, nil
}

// Hex parses a hexidecimal formatted peerID
func FromHex(s string) (PeerID, error) {
	bs, err := hex.DecodeString(s)
	if err != nil {
		return PeerID{}, err
	}
	return Make(bs)

}

// String returns a hexidecimal formatted peerID (just an 8-char prefix)
func (p PeerID) String() string {
	return hex.EncodeToString(p[:4])
}
