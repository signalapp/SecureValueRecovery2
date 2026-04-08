// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"testing"
)

func TestSequenceNumberCmp(t *testing.T) {
	for _, test := range []struct {
		a    sequenceNumber
		b    sequenceNumber
		want int
	}{
		{
			a:    sequenceNumber{epoch: 1, seq: 1},
			b:    sequenceNumber{epoch: 1, seq: 1},
			want: 0,
		},
		{
			a:    sequenceNumber{epoch: 2, seq: 1},
			b:    sequenceNumber{epoch: 1, seq: 1},
			want: 1,
		},
		{
			a:    sequenceNumber{epoch: 1, seq: 2},
			b:    sequenceNumber{epoch: 1, seq: 1},
			want: 1,
		},
		{
			a:    sequenceNumber{epoch: 20, seq: 1},
			b:    sequenceNumber{epoch: 1, seq: 1},
			want: 19,
		},
		{
			a:    sequenceNumber{epoch: 1, seq: 20},
			b:    sequenceNumber{epoch: 1, seq: 1},
			want: 19,
		},
	} {
		if got := test.a.cmp(test.b); got != test.want {
			t.Errorf("%#v cmp> %#v: want %d got %d", test.a, test.b, test.want, got)
		}
		if got := test.b.cmp(test.a); got != -test.want {
			t.Errorf("%#v <cmp %#v: want %d got %d", test.a, test.b, -test.want, got)
		}
	}
}
