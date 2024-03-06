// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package service creates and initializes all components required to run an SVR instance
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/dispatch"
	"github.com/signalapp/svr2/enclave"
	"github.com/signalapp/svr2/health"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peer"
	"github.com/signalapp/svr2/peer/peerdb"
	"github.com/signalapp/svr2/raftmanager"
	"github.com/signalapp/svr2/rate"
	"github.com/signalapp/svr2/util"
	"github.com/signalapp/svr2/web/handlers"
	"github.com/signalapp/svr2/web/middleware"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	pb "github.com/signalapp/svr2/proto"
	_ "net/http/pprof"
)

// Start starts all SVR components and only returns when a component has encountered an
// unrecoverable error or the provided context has been cancelled.
func Start(ctx context.Context, hconfig *config.Config, authenticator auth.Auth, enc enclave.Enclave) error {
	g, ctx := errgroup.WithContext(ctx)

	// Start up the control server immediately, for debugging and liveness checking.
	// Use DefaultServeMux, since it's got PProf stuff already attached by net/http/pprof.
	controlMux := http.DefaultServeMux
	healthErr := errors.New("joining raft")
	live, ready := health.New("live", healthErr), health.New("ready", healthErr)
	controlMux.Handle("/health/live", middleware.Instrument(live))
	controlMux.Handle("/health/ready", middleware.Instrument(ready))
	g.Go(func() error {
		logger.Infof("Starting control http server on %v", hconfig.ControlListenAddr)
		return http.ListenAndServe(hconfig.ControlListenAddr, controlMux)
	})

	enclaveMessages, nodeID := enc.OutputMessages(), enc.PID()

	logger.WithGlobal(zap.String("me", nodeID.String()))
	logger.Infow("created enclave")

	txGen := &util.TxGenerator{}

	dispatcher := dispatch.New(hconfig.Raft, txGen, enc, enclaveMessages)

	// listen for peer network requests
	ln, err := net.Listen("tcp", hconfig.PeerAddr)
	if err != nil {
		logger.Fatalf("failed to net.listen: %v", err)
	}
	peerServer := peer.NewPeerServer(ctx, nodeID, dispatcher)
	g.Go(func() error { return peerServer.Listen(ln) })

	logger.Infof("started peer server on %v", ln.Addr())

	logger.Infof("Starting Redis server on %v", hconfig.Redis.Addrs)
	peerDB := peerdb.New(hconfig.Redis)

	// let other peers look us up by our nodeID
	insertCtx, insertCancel := context.WithTimeout(ctx, time.Minute)
	if err := peerDB.Insert(insertCtx, nodeID, hconfig.PeerAddr, hconfig.InitialRedisPeerDBTTL); err != nil {
		logger.Fatalf("failed to update peerdb : %v", err)
	}
	insertCancel()

	logger.Infof("built peer lookup")

	// create network senders
	peerClient := peer.NewPeerClient(ctx, nodeID, peerDB, &hconfig.Peer, dispatcher)
	g.Go(func() error { return peerClient.Run() })

	// now that everything's wired up, start processing enclave requests
	g.Go(func() error { return dispatcher.Run(ctx, peerClient) })

	rateLimiter := rate.NewConfiguredLimiter(hconfig)

	// set up http server
	clientMux := http.NewServeMux()
	clientMux.Handle(fmt.Sprintf("/v1/%s", hconfig.EnclaveID),
		middleware.Instrument(middleware.AuthCheck(authenticator,
			middleware.RateLimit(rateLimiter, handlers.NewWebsocket(&hconfig.Request, dispatcher)))))
	clientMux.Handle("/v1/delete",
		middleware.Instrument(middleware.AuthCheck(authenticator,
			middleware.RateLimit(rateLimiter, handlers.NewDeleteBackup(dispatcher)))))

	// control endpoints
	controlMux.Handle("/control/loglevel", middleware.Instrument(handlers.NewSetLogLevel(hconfig, dispatcher)))
	controlMux.Handle("/control", middleware.Instrument(handlers.NewControl(dispatcher)))

	g.Go(func() error {
		logger.Infof("Starting client http server on %v", hconfig.ClientListenAddr)
		return http.ListenAndServe(hconfig.ClientListenAddr, clientMux)
	})

	// The enclave is up and the servers are serving, start checking liveness.
	g.Go(func() error { return livenessChecks(ctx, dispatcher, live, hconfig) })

	// wait until we successfully create a raft group or join an existing one
	raftManager := raftmanager.New(nodeID, dispatcher, peerDB, hconfig)
	joinCtx, joinCancel := context.WithTimeout(ctx, time.Minute)
	if err := raftManager.CreateOrJoin(joinCtx); err != nil {
		logger.Fatalf("failure to join raft : %v", err)
	}
	joinCancel()

	// Successfully joined raft, periodically refresh our peerdb status
	g.Go(func() error {
		return raftManager.RunRefresher(ctx, func(innerCtx context.Context, info raftmanager.EnclaveJoinInfo) error {
			timeoutCtx, cancel := context.WithTimeout(innerCtx, time.Minute)
			defer cancel()
			return peerDB.JoinedRaft(timeoutCtx, nodeID, info.IsLeader, hconfig.PeerAddr, hconfig.RecurringRedisPeerDBTTL)
		})
	})

	// Fully capable of servicing user requests, mark ready.
	ready.Set(nil)

	sigtermC := make(chan os.Signal, 1)
	signal.Notify(sigtermC, os.Signal(syscall.SIGTERM))
	g.Go(func() error {
		select {
		case <-sigtermC:
			logger.Errorf("Received SIGTERM, gracefully shutting down")
			// If we're the leader, stop being the leader.
			for sleep := time.Second * 0; ; sleep += time.Second {
				time.Sleep(sleep) // first time will not sleep
				logger.Errorf("Relinquishing Raft leadership")
				// We send both requests, but we retry both requests until both succeed.
				// This will allow us to retry when, for example, two replicas try to remove
				// themselves at the same time when only one membership change is allowed at once.
				_, err1 := dispatcher.SendTransaction(&pb.HostToEnclaveRequest{
					Inner: &pb.HostToEnclaveRequest_RelinquishLeadership{RelinquishLeadership: true},
				})
				logger.Errorf("Requesting removal from Raft")
				_, err2 := dispatcher.SendTransaction(&pb.HostToEnclaveRequest{
					Inner: &pb.HostToEnclaveRequest_RequestRemoval{RequestRemoval: true},
				})
				if err1 == nil && err2 == nil {
					break
				}
				logger.Errorf("Failed to remove self:  leadership=[%v] remove=[%v]", err1, err2)
			}
			logger.Errorf("Done gracefully shutting down, exiting")
			return errors.New("SIGTERM")
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	return g.Wait()
}

func wrapErr(in string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", in, err)
}

func livenessChecks(ctx context.Context, dispatcher *dispatch.Dispatcher, live *health.Health, cfg *config.Config) error {
	ticker := time.NewTicker(cfg.LocalLivenessCheckPeriod)
	defer ticker.Stop()
	logger.Infof("Starting initial liveness check")
	err := livenessCheck(ctx, dispatcher, cfg)
	live.Set(err)
	logger.Infof("Starting liveness check loop, initial liveness check: %v", err)
	for {
		select {
		case <-ctx.Done():
			live.Set(wrapErr("livenessChecks context", ctx.Err()))
			return ctx.Err()
		case <-ticker.C:
			live.Set(livenessCheck(ctx, dispatcher, cfg))
		}
	}
}

func livenessCheck(ctx context.Context, dispatcher *dispatch.Dispatcher, cfg *config.Config) error {
	// dispatcher.SendTransaction could block forever if something's wrong with the
	// enclave... make sure to use a timeout!
	dispatcherErr := make(chan error, 1)
	ctx, cancel := context.WithTimeout(ctx, cfg.LocalLivenessCheckTimeout)
	defer cancel()
	go func() {
		if resp, err := dispatcher.SendTransaction(&pb.HostToEnclaveRequest{
			Inner: &pb.HostToEnclaveRequest_GetEnclaveStatus{GetEnclaveStatus: true},
		}); err != nil {
			// We were unable to talk to the enclave
			dispatcherErr <- wrapErr("dispatcher.SendTransaction", err)
		} else if s, ok := resp.Inner.(*pb.HostToEnclaveResponse_Status); ok {
			// We were able to talk to the enclave, but it couldn't give us a status
			dispatcherErr <- wrapErr("HostToEnclaveResponse_Status", s.Status)
		} else {
			// We could get a status from the enclave
			dispatcherErr <- nil
		}
	}()
	select {
	case err := <-dispatcherErr:
		return wrapErr("dispatcherErr", err)
	case <-ctx.Done():
		return wrapErr("livenessCheck context", ctx.Err())
	}
}
