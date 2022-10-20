// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package raftmanager provides utilities for joining or creating raft groups
package raftmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	pb "github.com/signalapp/svr2/proto"
)

type MemberFinder interface {
	// FindRaftMember finds an existing raft member to join, or return self if raft group should be created
	FindRaftMember(ctx context.Context, me peerid.PeerID, localPeerAddr string) (peerid.PeerID, error)
}

// EnclaveRequester provides a request/response channel to the enclave
type EnclaveRequester interface {
	// SendTransaction sends a request to the enclave and returns the enclave's response.
	// Implementations must tag the provided request with a requestID.
	SendTransaction(req *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error)
}

// RaftManager can be used to create a new raft group, or join an existing one.
type RaftManager struct {
	config           *config.Config
	me               peerid.PeerID
	localPeerAddr    string
	enclaveRequester EnclaveRequester
	memberFinder     MemberFinder
	isMember         bool // true once a successful call to CreateOrJoin is made
}

func New(me peerid.PeerID, enclaveRequester EnclaveRequester, memberFinder MemberFinder, config *config.Config) *RaftManager {
	return &RaftManager{
		config,
		me,
		config.PeerAddr,
		enclaveRequester,
		memberFinder,
		false,
	}
}

// MarkLiveFun is used to indicate to other peers that
// this peer is a good candidate to join raft with
type MarkLiveFun func(ctx context.Context) error

// RunRefresher periodically checks the enclave to verify this peer has good connectivity
// to other raft nodes, and if so calls the provided MarkLiveFun
func (r *RaftManager) RunRefresher(ctx context.Context, markLive MarkLiveFun) error {
	if !r.isMember {
		// only allow starting the refresher once we're part of raft
		return errors.New("only raft members can update their peerdb status")
	}

	// always initially mark ourselves as live
	if err := markLive(ctx); err != nil {
		return err
	}

	logger.Infof("Starting raft status refresher, will refresh every %v", r.config.Raft.RefreshStatusDuration)

	// periodically query the enclave and make sure we're still a reasonable candidate for others to join
	ch := time.Tick(r.config.Raft.RefreshStatusDuration)
	for {
		select {
		case <-ch:
			if err := r.enclaveJoinable(); err != nil {
				logger.Warnw("could not get enclave status", "err", err)
			} else if err := markLive(ctx); err != nil {
				logger.Warnw("failed to mark ourselves as joinable", "err", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// enclaveJoinable returns nil if other peers may use this node to join a raft cluster
func (r *RaftManager) enclaveJoinable() error {
	resp, err := r.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_GetEnclaveStatus{
			GetEnclaveStatus: true,
		},
	})
	if err != nil {
		return err
	}
	if v, ok := resp.Inner.(*pb.HostToEnclaveResponse_Status); ok && v.Status != pb.Error_OK {
		return v.Status
	}
	v, ok := resp.Inner.(*pb.HostToEnclaveResponse_GetEnclaveStatusReply)
	if !ok {
		return fmt.Errorf("unexpected enclave reply %v", resp)
	}

	partitionStatus := v.GetEnclaveStatusReply
	if partitionStatus == nil {
		return errors.New("unexpected enclave reply, missing partition status")
	}

	if partitionStatus.RaftState != pb.RaftState_RAFTSTATE_LOADED_PART_OF_GROUP {
		return fmt.Errorf("not part of raft group, state: %v", partitionStatus.RaftState)
	}
	return nil
}

// CreateOrJoin finds and joins an existing raft group or creates a new raft group
// if one cannot be found. Errors from this method indicate an enclave join operation
// has failed.
func (r *RaftManager) CreateOrJoin(ctx context.Context) error {
	raftPeer, err := r.memberFinder.FindRaftMember(ctx, r.me, r.localPeerAddr)
	if err != nil {
		return errors.New("failed to fetch raft peers")
	}
	if raftPeer == r.me {
		logger.Infow("attempting to create a new raft group")
		if err := r.createRaft(); err != nil {
			return err
		}
	} else {
		logger.Infow("attempting to join existing raft group", "peerID", raftPeer)
		if err := r.joinExistingRaftPeer(raftPeer); err != nil {
			return err
		}
	}

	//  refresh attestation now that we've joined the raft group
	logger.Infow("attempting to refresh attestation")
	if err := r.refreshAttestation(); err != nil {
		return err
	}
	r.isMember = true
	return nil
}

func (r *RaftManager) refreshAttestation() error {
	// send a message to the enclave to update attestation
	return r.sendToEnclave(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_RefreshAttestation{
			RefreshAttestation: &pb.RefreshAttestation{RotateClientKey: false},
		},
	})
}

func (r *RaftManager) createRaft() error {
	// send a message to the enclave to create a raft group
	return r.sendToEnclave(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_CreateNewRaftGroup{CreateNewRaftGroup: true},
	})
}

// joinExistingRaftPeer joins a raft group by requesting membership from the provided peer
func (r *RaftManager) joinExistingRaftPeer(peer peerid.PeerID) error {
	// send a message to the enclave to join the raft group using the provided peer
	return r.sendToEnclave(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_JoinRaft{
			JoinRaft: &pb.JoinRaftRequest{PeerId: peer[:]},
		},
	})
}

// sendToEnclave sends a request to the enclave and verify the response is Error_OK
func (r *RaftManager) sendToEnclave(req *pb.HostToEnclaveRequest) error {
	reply, err := r.enclaveRequester.SendTransaction(req)

	if err != nil {
		return fmt.Errorf("failed to send to enclave : %w", err)
	}

	if reply == nil {
		return fmt.Errorf("unexpected enclave response (nil)")
	}

	status, ok := reply.Inner.(*pb.HostToEnclaveResponse_Status)
	if !ok {
		return errors.New("unexpected enclave response")
	}
	if status.Status != pb.Error_OK {
		return fmt.Errorf("failed to join raft: %w", status.Status)
	}
	return nil
}
