// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"github.com/signalapp/svr2/peerid"

	pb "github.com/signalapp/svr2/proto"
)

type Enclave interface {
	PID() peerid.PeerID
	OutputMessages() <-chan *pb.EnclaveMessage
	SendMessage(msgPB *pb.UntrustedMessage) error
}
