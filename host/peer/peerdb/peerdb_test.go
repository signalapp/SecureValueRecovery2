// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peerdb

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/util"
)

func TestPeerDB(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	peerdb := New(config.RedisConfig{
		Addrs: []string{s.Addr()},
		Name:  "test",
	})
	defer peerdb.Close()

	peer1 := [32]byte{1}
	peer2 := [32]byte{2}
	if err := peerdb.Insert(ctx, peer1, "host1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := peerdb.Insert(ctx, peer2, "host2", time.Minute); err != nil {
		t.Fatal(err)
	}

	host1, err := peerdb.Lookup(context.Background(), peer1)
	if err != nil {
		t.Error(err)
	}
	if host1 == nil || *host1 != "host1" {
		t.Errorf("Lookup(%v)=%v, want %v", peer1, host1, "host1")
	}

	host2, err := peerdb.Lookup(context.Background(), peer2)
	if err != nil {
		t.Error(err)
	}
	if host2 == nil || *host2 != "host2" {
		t.Errorf("Lookup(%v)=%v, want %v", peer1, host1, "host2")
	}
}

func TestMissingPeer(t *testing.T) {
	s := miniredis.RunT(t)
	peerdb := New(config.RedisConfig{
		Addrs: []string{s.Addr()},
		Name:  "test",
	})
	defer peerdb.Close()

	peer1 := [32]byte{1}
	v, err := peerdb.Lookup(context.Background(), peer1)
	if err != nil {
		t.Errorf("missing peer shouldn't error: %v", err)
	}
	if v != nil {
		t.Errorf("Lookup(%v)=%v, want nil", peer1, v)
	}

}

type EntryStatus int

const (
	EntryStatusMissing          EntryStatus = iota
	EntryStatusSelf                         // self
	EntryStatusNonMember                    // peer that isn't in the raft cluster
	EntryStatusMember                       // peer that is in the raft cluster
	EntryStatusRecentMember                 // peer that has been seen recently
	EntryStatusRecentLeader                 // peer that has been seen recently and is the leader
	EntryStatusMatchingHostname             // peer with the same hostname as we have
)

func TestCreationLock(t *testing.T) {
	s := miniredis.RunT(t)
	peerdb := New(config.RedisConfig{
		Addrs: []string{s.Addr()},
		Name:  "test",
	})
	defer peerdb.Close()

	peer0 := [32]byte{byte(0)}
	peer1 := [32]byte{byte(1)}
	if err := peerdb.acquireCreationLock(context.Background(), peer0); err != nil {
		t.Error(err)
	}
	if err := peerdb.acquireCreationLock(context.Background(), peer0); err == nil {
		t.Error("lock can only be acquired once")
	}
	if err := peerdb.acquireCreationLock(context.Background(), peer1); err == nil {
		t.Error("lock can only be acquired once")
	}
}

func TestFindRaftMember(t *testing.T) {
	tests := []struct {
		name        string
		peers       []EntryStatus
		expectedIdx int
	}{
		{"pick_member_1", []EntryStatus{EntryStatusMember}, 0},
		{"pick_member", []EntryStatus{EntryStatusSelf, EntryStatusMember, EntryStatusNonMember}, 1},
		{"pick_recent", []EntryStatus{EntryStatusNonMember, EntryStatusMember, EntryStatusMember, EntryStatusRecentMember}, 3},
		{"pick_non_leader", []EntryStatus{EntryStatusRecentLeader, EntryStatusMember, EntryStatusMember, EntryStatusRecentMember}, 3},
		{"no_members", []EntryStatus{EntryStatusSelf, EntryStatusNonMember, EntryStatusMissing, EntryStatusMatchingHostname}, 0},
		{"only_leader", []EntryStatus{EntryStatusRecentLeader, EntryStatusNonMember}, 0},
		{"only_self", []EntryStatus{EntryStatusSelf}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miniredis.RunT(t)
			peerdb := New(config.RedisConfig{
				Addrs: []string{s.Addr()},
				Name:  "test",
			})
			defer peerdb.Close()

			oldTime := time.Unix(100, 0)
			recentTime := time.Unix(101, 0)
			recentLeaderTime := time.Unix(102, 0)
			peerdb.clock = util.TestAt(oldTime)

			// add peers to redis according to their status
			self := [32]byte{byte(255)}
			peers := make([]peerid.PeerID, len(tt.peers))
			for i := 0; i < len(tt.peers); i++ {
				peers[i] = [32]byte{byte(i)}
				hostname := fmt.Sprintf("host%v", i)
				var err error
				switch tt.peers[i] {
				case EntryStatusMissing:
					continue
				case EntryStatusNonMember:
					err = peerdb.Insert(context.Background(), peers[i], hostname, time.Minute)
				case EntryStatusMember:
					err = peerdb.JoinedRaft(context.Background(), peers[i], false, hostname, time.Minute)
				case EntryStatusRecentMember:
					peerdb.clock = util.TestAt(recentTime)
					err = peerdb.JoinedRaft(context.Background(), peers[i], false, hostname, time.Minute)
					peerdb.clock = util.TestAt(oldTime)
				case EntryStatusRecentLeader:
					peerdb.clock = util.TestAt(recentLeaderTime)
					err = peerdb.JoinedRaft(context.Background(), peers[i], true, hostname, time.Minute)
					peerdb.clock = util.TestAt(oldTime)
				case EntryStatusMatchingHostname:
					err = peerdb.JoinedRaft(context.Background(), peers[i], false, "self", time.Minute)
				case EntryStatusSelf:
					self = peers[i]
				}
				if err != nil {
					t.Error(err)
				}
			}

			// add ourself to redis too
			if err := peerdb.Insert(context.Background(), self, "self", time.Minute); err != nil {
				t.Error(err)
			}

			if tt.expectedIdx == -1 {
				// expect a timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
				defer cancel()
				_, err := peerdb.FindRaftMember(ctx, self, "self")
				if err != ctx.Err() {
					t.Errorf("findRaftMember() = %v, want %v", err, ctx.Err())
				}
				return
			}

			got, err := peerdb.FindRaftMember(context.Background(), self, "self")
			if err != nil {
				t.Error(err)
			}
			if want := peers[tt.expectedIdx]; got != want {
				t.Errorf("FindRaftMember() = %v, want %v", got, want)
			}
		})
	}
}
