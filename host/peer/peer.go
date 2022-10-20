// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package peer implements the host to host network protocol for sending messages between enclaves
package peer

import (
	pb "github.com/signalapp/svr2/proto"
)

var (
	maxMessageLength uint64 = 1024 * 1024 * 128
)

type EnclaveSender interface {
	// Send sends a message to the enclave and potentially waits for a reply
	Send(p *pb.UntrustedMessage) (*pb.EnclaveMessage, error)
}
