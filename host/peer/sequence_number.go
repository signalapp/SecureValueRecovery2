// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"errors"
	"fmt"

	pb "github.com/signalapp/svr2/proto"
)

type sequenceNumber struct {
	epoch uint32
	seq   uint64
}

// follows returns true if this seqeunce number directly follows the provided sequence number.
// This is the case if either it's the next in the sequence, or it is from a greater epoch.
func (s sequenceNumber) follows(pred sequenceNumber) bool {
	return (s.epoch > pred.epoch && s.seq == 0) || (s.epoch == pred.epoch && s.seq == pred.seq+1)
}

// next returns the sequenceNumber of the next message within an enclave peer session
func (s sequenceNumber) next() sequenceNumber {
	return sequenceNumber{
		epoch: s.epoch,
		seq:   s.seq + 1,
	}
}

// nextEpoch returns the sequenceNumber of the next epoch, typically denoting the start of a new
// enclave peer session
func (s sequenceNumber) nextEpoch() sequenceNumber {
	return sequenceNumber{
		epoch: s.epoch + 1,
		seq:   0,
	}
}

// cmp compares two sequence numbers
//
// returns:
//
//	 < 0 if this is less than the provided sequenceNumber
//	== 0 if this is equal to the provided sequenceNumber
//	 > 0 if this is greater than the provided sequenceNumber
func (s sequenceNumber) cmp(o sequenceNumber) int {
	if ecmp := int(s.epoch - o.epoch); ecmp != 0 {
		return ecmp
	}
	return int(s.seq - o.seq)
}

func (s sequenceNumber) proto() *pb.SequenceNumber {
	return &pb.SequenceNumber{
		Epoch: s.epoch,
		Seq:   s.seq,
	}
}

func makeSeqno(p *pb.SequenceNumber) (sequenceNumber, error) {
	if p == nil {
		return sequenceNumber{}, errors.New("expected a sequence number present on message")
	}
	return sequenceNumber{
		epoch: p.Epoch,
		seq:   p.Seq,
	}, nil
}

func (s sequenceNumber) String() string {
	return fmt.Sprintf("%v:%v", s.epoch, s.seq)
}
