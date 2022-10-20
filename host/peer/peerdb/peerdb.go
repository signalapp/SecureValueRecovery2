// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/util"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/signalapp/svr2/proto"
)

// PeerDB associates the enclave level PeerID with the external hostname of the peer
type PeerDB struct {
	cfg               config.RedisConfig
	rdb               *redis.ClusterClient
	peersKeyPrefix    string // key prefix for peer values.  You can't set TTLs on individual entries in a hash, so we set all peers as individual values.
	createRaftKeyName string // key used for to exclusivity for raft group creation
	clock             util.Clock
}

// New creates a PeerDB
func New(cfg config.RedisConfig) *PeerDB {
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    cfg.Addrs,
		Password: cfg.Password,
	})
	return &PeerDB{
		cfg:               cfg,
		rdb:               rdb,
		peersKeyPrefix:    fmt.Sprintf("%s::%s::", cfg.Name, "peers"),
		createRaftKeyName: fmt.Sprintf("%s::%s", cfg.Name, "create"),
		clock:             util.RealClock,
	}
}

func (p *PeerDB) peerKey(peer peerid.PeerID) string {
	return p.peersKeyPrefix + hex.EncodeToString(peer[:])
}

func (p *PeerDB) peerFromKey(key string) (peerid.PeerID, error) {
	if !strings.HasPrefix(key, p.peersKeyPrefix) {
		return peerid.PeerID{}, fmt.Errorf("key does not have peer key prefix")
	} else if bytes, err := hex.DecodeString(key[len(p.peersKeyPrefix):]); err != nil {
		return peerid.PeerID{}, fmt.Errorf("hex-decoding key: %v", err)
	} else {
		return peerid.Make(bytes)
	}
}

// Lookup fetches a hostname from the PeerDB from the hostname
func (p *PeerDB) Lookup(ctx context.Context, peer peerid.PeerID) (*string, error) {
	bs, err := p.rdb.Get(ctx, p.peerKey(peer)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	peerEntry := pb.PeerEntry{}
	if err := protojson.Unmarshal(bs, &peerEntry); err != nil {
		return nil, err
	}
	return &peerEntry.Addr, nil
}

// Close should be called when the PeerDB is no longer used
func (p *PeerDB) Close() error {
	return p.rdb.Close()
}

// Insert adds a peer entry keyed by peerID to the PeerDB
//
// This method retries until the insert succeeds or the provided context is cancelled
func (p *PeerDB) Insert(ctx context.Context, me peerid.PeerID, addr string, ttl time.Duration) error {
	return p.insert(ctx, me, addr, false, ttl)
}

// JoinedRaft updates a peer entry to indicate that it has joined the raft cluster
//
// This method retries until the insert succeeds or the provided context is cancelled
func (p *PeerDB) JoinedRaft(ctx context.Context, me peerid.PeerID, addr string, ttl time.Duration) error {
	return p.insert(ctx, me, addr, true, ttl)
}

func (p *PeerDB) insert(ctx context.Context, me peerid.PeerID, addr string, isRaftMember bool, ttl time.Duration) error {
	return util.RetryWithBackoff(ctx, func() error {
		logger.Debugw("Attempting to add self to peerdb", "addr", addr, "raftmember", isRaftMember)
		currentTime := p.clock.Now().Unix()
		m := pb.PeerEntry{Addr: addr, LastUpdateTs: currentTime, RaftMember: isRaftMember}
		if isRaftMember {
			m.JoinTs = currentTime
		}
		bs, err := protojson.Marshal(&m)
		if err != nil {
			return err
		}
		if err := p.rdb.Set(ctx, p.peerKey(me), bs, ttl).Err(); err != nil {
			logger.Errorw("rdb.Set for PeerDB insert error", "err", err)
			return err
		}
		return nil
	}, p.cfg.MinSleepDuration, p.cfg.MaxSleepDuration)

}

// FindRaftMember returns a member of an existing raft group that may be used to join raft
// If no such eligible members exist, this method may return `me`, indicating that it is safe
// to create a raft group instead of joining one.
func (p *PeerDB) FindRaftMember(ctx context.Context, me peerid.PeerID, localPeerAddr string) (peerid.PeerID, error) {
	// retry until we find an eligible peer or we acquire the exclusive creation lock
	return util.RetrySupplierWithBackoff(ctx, func() (peerid.PeerID, error) {
		peers, err := p.list(ctx)
		if err != nil {
			logger.Infow("failed to fetch raft members", "err", err)
			return peerid.PeerID{}, err
		}

		var peerIDs []peerid.PeerID
		for k, v := range peers {
			if k == me || v.Addr == localPeerAddr {
				continue
			}
			if !v.RaftMember {
				continue
			}
			peerIDs = append(peerIDs, k)
		}

		if len(peerIDs) == 0 {
			logger.Infow("no available raft members, attempting to get creation lock")
			if err := p.acquireCreationLock(ctx, me); err != nil {
				// someone else probably got the lock, so our next attempt may go better
				logger.Infow("failed to get creation lock", "err", err)
				return peerid.PeerID{}, errors.New("no peers available and could not get creation lock")
			}
			return me, nil
		}
		// sort so the most recently joined member is first
		sort.Slice(peerIDs, func(i int, j int) bool {
			return peers[peerIDs[j]].JoinTs < peers[peerIDs[i]].JoinTs
		})
		logger.Infow("found joinable raft peer", "peerID", peerIDs[0])
		return peerIDs[0], nil

	}, p.cfg.MinSleepDuration, p.cfg.MaxSleepDuration)
}

// acquireCreationLock attempts to acquire an exclusive lock to create a raft group
// on success, this node may create a new raft group
// on error, this node should re-attempt to join from a peer
func (p *PeerDB) acquireCreationLock(ctx context.Context, me peerid.PeerID) error {
	got, err := p.rdb.SetNX(ctx, p.createRaftKeyName, me[:], 0).Result()
	if err != nil {
		return err
	}
	if !got {
		return errors.New("failure to get exclusive creation lock")
	}
	return nil
}

// list fetches all the peers in the database
func (p *PeerDB) list(ctx context.Context) (map[peerid.PeerID]*pb.PeerEntry, error) {
	var mu sync.Mutex
	var shardResults [][]string

	err := p.rdb.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
		mu.Lock()
		defer mu.Unlock()
		keys, err := shard.Keys(ctx, p.peersKeyPrefix+"*").Result()
		if err != nil {
			return err
		}
		logger.Debugf("Retrieved %v peers from peerdb shard", len(keys))
		shardResults = append(shardResults, keys)
		return nil
	})

	if err != nil {
		return nil, err
	}

	ret := make(map[peerid.PeerID]*pb.PeerEntry)
	for _, keys := range shardResults {
		for _, key := range keys {
			peerID, err := p.peerFromKey(key)
			if err != nil {
				return nil, fmt.Errorf("invalid peer key: %v", key)
			}
			v, err := p.rdb.Get(ctx, key).Result()
			if err == redis.Nil {
				// Key expired since call to Keys
				continue
			} else if err != nil {
				return nil, fmt.Errorf("unable to get peer key %v: %v", key, err)
			}
			peerEntry := &pb.PeerEntry{}
			if err := protojson.Unmarshal([]byte(v), peerEntry); err != nil {
				return nil, err
			}
			ret[peerID] = peerEntry
		}
	}
	logger.Infof("Retrieved %v peers from peerdb", len(ret))
	return ret, nil
}
