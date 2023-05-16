// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/util"
	"golang.org/x/sync/errgroup"

	pb "github.com/signalapp/svr2/proto"
)

// PeerLookup provides a way to get a peer's hostname from its PeerID
type PeerLookup interface {
	// Lookup takes a PeerID and attempts to find the associated hostname. If the peer is not
	// found, the returned string and error will be nil
	Lookup(context.Context, peerid.PeerID) (*string, error)
}

// PeerClient can be used to send PeerMessages to remote peers
//
// PeerClient routes PeerMessages to dedicated goroutines (peerSenders)
// that handle the peer protocol handshake and  append sequence numbers to every
// PeerMessage.
//
// Usually the peer client must store outbound messages until they are acked. If the TCP
// connection between client and server is terminated, the client must resend pending messages to the remote
// peer on reconnection. However, there are certain cases where a client will declare message bankruptcy,
// and drop these pending messages. This can happen when:
//   - A caller is sending messages faster than the peerClient (or the remote peer server) can process them
//   - We have been trying and failing to connect to a peer server for a substantial period of time
//
// In the first case, the client may try to keep the underlying TCP connection open, but drop pending messages. In the
// second case, the client will "abandon" the peer and not attempt to connect to the server until a reset is received.
// When messages are dropped, an error will be returned to the caller indicating that the enclave-to-enclave session
// must be re-established.
//
//	┌──────────────┐      ┌──────────────┐
//	│              │      │   require    │
//	│ unknown peer │      │    reset     │
//	│              │      │              │
//	└───────┬──────┘      └─┬───────────▲┘
//	        │               │           │
//	 any    │        RST/SYN│           │
//	message │               │           │
//	        │               │           │
//	┌───────▼──────┐◄───────┘           │
//	│              │                    │
//	│   buffered   ├────────────────────┘
//	│    sending   │     buffer full /
//	└──────────────┘     server unresponsive
type PeerClient struct {
	me         peerid.PeerID      // sender's peerID
	cfg        *config.PeerConfig // client configuration
	peerLookup PeerLookup         // fetches the remote endpoint associated with a PeerID
	eg         *errgroup.Group    // indicates one of the child senders has closed or hit an unrecoverable error
	ctx        context.Context

	sendersMu      sync.Mutex
	senders        map[peerid.PeerID]*peerSender // map of live peerSenders
	abandonedPeers map[peerid.PeerID]bool        // set of peers we've previously talked to but now have abandoned
}

var (
	activeConnectionsGauge   = []string{"peer", "client", "activeConnections"}
	outboundQueueLengthGauge = []string{"peer", "client", "outboundQueueLength"}
	connectAttemptCounter    = []string{"peer", "client", "connectAttempt"}
	abandonedPeerCounter     = []string{"peer", "client", "abandon"}
	resendCounter            = []string{"peer", "client", "resend"}
	sendCounter              = []string{"peer", "client", "send"}
	ackCounter               = []string{"peer", "client", "ack"}
	epochCounter             = []string{"peer", "client", "epoch"}
)

// NewPeerClient creates a PeerClient
func NewPeerClient(
	ctx context.Context,
	me peerid.PeerID,
	peerLookup PeerLookup,
	cfg *config.PeerConfig) *PeerClient {

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		// finishes if the caller cancels or any child experiences an error
		<-ctx.Done()
		return ctx.Err()
	})

	return &PeerClient{
		me:             me,
		cfg:            cfg,
		peerLookup:     peerLookup,
		eg:             eg,
		ctx:            ctx,
		senders:        make(map[peerid.PeerID]*peerSender),
		abandonedPeers: make(map[peerid.PeerID]bool),
	}
}

// Run runs until the PeerClient experiences a terminal error or is shutdown
func (p *PeerClient) Run() error {
	return p.eg.Wait()
}

var ErrResetConnection = errors.New("connection must be reset")
var errAbandonPeer = errors.New("peer connect timed out")

// Send a message to a peer.
//
// ErrResetConnection may be returned if we cannot deliver messages to this peer. In this case
// messages will be dropped and the caller must reset their peer session.
func (p *PeerClient) Send(msg *pb.PeerMessage) error {
	peerID, err := peerid.Make(msg.PeerId)
	if err != nil {
		return err
	}
	sender, err := p.getOrCreateSender(msg, peerID)
	if err != nil {
		return err
	}
	return sender.queueMessage(msg)
}

// getOrCreateSender returns the existing peerSender for the peerID, or creates a new one if it doesn't exist
func (p *PeerClient) getOrCreateSender(msg *pb.PeerMessage, peerID peerid.PeerID) (*peerSender, error) {
	p.sendersMu.Lock()
	defer p.sendersMu.Unlock()
	metrics.SetGauge(activeConnectionsGauge, float32(len(p.senders)))
	sender, ok := p.senders[peerID]
	if ok {
		return sender, nil
	}

	// check if we've had a sender for this peer in the past
	if p.abandonedPeers[peerID] {
		// This is a peer we previously decided to abandon.
		if !isEstablishing(msg) {
			// We can resume talking to it, but any new communication
			// must first establish a new enclave connection
			logger.Warnw("attempting to send non-establishing message to previously abandoned peer",
				"peerID", peerID)
			return nil, ErrResetConnection
		}

		// otherwise, we can create a new connection for it it
		delete(p.abandonedPeers, peerID)
		logger.Infow("attempting to reconnect to previously abandoned peer", "peerID", peerID)
	} else {
		logger.Infow("creating new peerSender on first message to peer", "peerID", peerID)
	}

	sender = newPeerSender(p.me, peerID, p.peerLookup, p.cfg)
	p.senders[peerID] = sender
	metrics.SetGauge(activeConnectionsGauge, float32(len(p.senders)))
	p.eg.Go(func() error {
		err := sender.run(p.ctx)

		// Remove the sender from the sender's map.
		// Note: There's a harmless race here. If a Send caller has already retrieved
		// their sender and is in the midst of calling queueMessage when the sender
		// exits, the message will never be processed. This is fine, because we want
		// to drop old messages anyway. Because queueMessage never blocks, there's no
		// deadlock concern either.
		p.sendersMu.Lock()
		defer p.sendersMu.Unlock()

		// a subsequent send will need to create a new sender
		delete(p.senders, peerID)

		if errors.Is(err, errAbandonPeer) {
			// remember if we gave up on this peer, so we know to reset our connect
			// if we communicate with them again.
			p.abandonedPeers[peerID] = true

			// not a fatal error
			return nil
		}

		return err
	})

	return sender, nil

}

func isEstablishing(msg *pb.PeerMessage) bool {
	switch msg.Inner.(type) {
	case *pb.PeerMessage_Syn, *pb.PeerMessage_Synack, *pb.PeerMessage_Rst:
		return true
	default:
		return false
	}
}

// peerSender handles PeerMessages for one particular peer
//
// peerSenders try to re-connect to the remote peer on errors
// and only stops running on unrecoverable errors
type peerSender struct {
	cfg        *config.PeerConfig                   // client configuration
	me         peerid.PeerID                        // the sending local peer
	remote     peerid.PeerID                        // the targeted remote peer
	peerLookup PeerLookup                           // name resolution for peers
	pending    []*pb.PeerConnectionData             // requests that might be resent
	lastAck    sequenceNumber                       // lastAck + 1 should be always be pending[0]'s sequence number
	tx         atomic.Pointer[chan *pb.PeerMessage] // on epoch bumps, old messages can be discarded so the send channel is atomically replaced
	labels     []metrics.Label                      // metric labels to attach to metrics from this sender
}

func newPeerSender(
	me, remote peerid.PeerID,
	peerLookup PeerLookup,
	cfg *config.PeerConfig) *peerSender {
	s := &peerSender{
		cfg:        cfg,
		me:         me,
		remote:     remote,
		peerLookup: peerLookup,
		pending:    nil,
		tx:         atomic.Pointer[chan *pb.PeerMessage]{},
		labels: []metrics.Label{{
			Name:  "peerID",
			Value: remote.String(),
		}},
	}
	c := make(chan *pb.PeerMessage, cfg.BufferSize)
	s.tx.Store(&c)
	return s
}

func (p *peerSender) run(ctx context.Context) error {

	peerAddr, err := p.lookupPeerAddr(ctx)
	if err != nil {
		// this peer has gone away
		logger.Warnw("could not lookup peer, giving up",
			"peerID", p.remote,
			"err", err)
		return errAbandonPeer
	}

	lastConnect := time.Now()
	sleepTime := time.Duration(0)
	for {
		if time.Since(lastConnect) > p.cfg.AbandonDuration {
			// we've been trying to connect to this peer for long enough, give up
			metrics.IncrCounterWithLabels(abandonedPeerCounter, 1, p.labels)
			return errAbandonPeer
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepTime):
		}

		// attempt to connect to peer
		metrics.IncrCounterWithLabels(connectAttemptCounter, 1, p.labels)
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			logger.Infow("Failed to connect to peer",
				"peerID", p.remote,
				"peer", peerAddr,
				"err", err)
			sleepTime = util.Clamp(sleepTime*2, p.cfg.MinSleepDuration, p.cfg.MaxSleepDuration)
			continue
		}

		// once connected, actually kickoff the sender
		done := make(chan error, 1)
		start := time.Now()
		go func() { done <- p.handleConnection(ctx, conn) }()
		select {
		case err := <-done:
			// error case, retry
			duration := time.Since(start)
			logger.Infow("Peer connection terminated",
				"peerID", p.remote,
				"peer", peerAddr,
				"err", err,
				"connected_duration", duration)

			// we don't want to hammer the peer if it is failing right away,
			// but we don't need to sleep max time if we've been connected for
			// a while. subtract out the amount of time we've been running for
			sleepTime = util.Clamp(sleepTime*2-duration, p.cfg.MinSleepDuration, p.cfg.MaxSleepDuration)

			var handshakeErr *errFailedHandshake
			if !errors.As(err, &handshakeErr) {
				// If we managed to actually get to send some data to the peer
				// restart the timer on detecting dead peers.
				lastConnect = time.Now()
			}
			continue
		case <-ctx.Done():
			// externally closed, close the connection and wait for handle to finish before exiting
			conn.Close()
			<-done
			return ctx.Err()
		}
	}
}

func (p *peerSender) lookupPeerAddr(ctx context.Context) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return util.RetrySupplierWithBackoff(ctx, func() (string, error) {
		// attempt to get the peer's host name
		addr, err := p.peerLookup.Lookup(ctx, p.remote)
		if err != nil {
			logger.Warnw("Failed to lookup peer", "peerID", p.remote, "err", err)
			return "", err
		}
		if addr == nil {
			// A peer that has been added to the raft group is not known to the host.
			// It was probably wiped out and it's redis entry was removed, mark it as
			// abandoned.
			logger.Warnw("Remote peer does not exist", "peerID", p.remote)
			cancel()
			return "", errors.New("remote peer does not exist")
		}
		return *addr, nil
	}, p.cfg.MinSleepDuration, p.cfg.MaxSleepDuration)
}

// queue a message to be sent by the run loop
func (p *peerSender) queueMessage(msg *pb.PeerMessage) error {
	var c chan *pb.PeerMessage
	if isEstablishing(msg) {
		// these messages indicate we don't care about previous messages, we can replace our
		// send channel with a fresh one
		c = make(chan *pb.PeerMessage, p.cfg.BufferSize)
		close(*p.tx.Swap(&c))
	} else {
		c = *p.tx.Load()
	}

	metrics.SetGaugeWithLabels(outboundQueueLengthGauge, float32(len(c)), p.labels)

	select {
	case c <- msg:
		return nil
	default:
		return ErrResetConnection
	}
}

// processAck drops acknowledged pending messages
func (p *peerSender) processAck(ack sequenceNumber) error {
	if ack.cmp(p.lastAck) < 0 {
		// this peer is buggy
		return fmt.Errorf("remote peer illegal ack %v, must be at least %v", ack, p.lastAck)
	}

	// drop any pending requests that have already been acked
	for len(p.pending) > 0 {
		seqno, err := makeSeqno(p.pending[0].Seqno)
		if err != nil {
			return err
		}
		if seqno.cmp(ack) > 0 {
			break
		}
		p.pending = p.pending[1:]
	}
	p.lastAck = ack
	return nil
}

type ackResult struct {
	ack sequenceNumber
	err error
}

// ackLoop forwards acks read from a connection until it is cancelled or hits an error
func (p *peerSender) ackLoop(ctx context.Context, r *bufio.Reader, ackOut chan ackResult) {
	for {
		ack, err := readAck(r)
		select {
		case ackOut <- ackResult{ack, err}:
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

type errFailedHandshake struct{ reason error }

func (e *errFailedHandshake) Error() string { return fmt.Sprintf("failed handshake: %v", e.reason) }

func (p *peerSender) handleConnection(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	logger := logger.With("peer", conn.RemoteAddr(), "peerID", p.remote)

	// handshake
	logger.Infow("writing hello")
	if err := writeHello(conn, p.me, p.remote); err != nil {
		return &errFailedHandshake{err}
	}
	reader := bufio.NewReader(conn)
	lastAck, err := readHelloAck(reader)
	if err != nil {
		return &errFailedHandshake{err}
	}

	// find out which messages haven't been received by the remote peer
	if err := p.processAck(lastAck); err != nil {
		return &errFailedHandshake{err}
	}
	logger.Infow("resending pending messages on connect",
		"last_ack", lastAck,
		"pending", len(p.pending))

	// resend any unacked messages
	currentSeqno := p.lastAck.next()

	for _, msg := range p.pending {
		metrics.IncrCounterWithLabels(resendCounter, 1, p.labels)
		err := writeFramed(conn, &pb.PeerConnectionMessage{Inner: &pb.PeerConnectionMessage_Data{Data: msg}})
		if err != nil {
			return fmt.Errorf("resend pending: %w", err)
		}
		currentSeqno = currentSeqno.next()
	}

	// goroutine to read ack responses and send up acks
	ackCtx, ackCancel := context.WithCancel(ctx)
	ackChan := make(chan ackResult)
	go p.ackLoop(ackCtx, reader, ackChan)
	// once we're done, cancel the ack reader
	defer ackCancel()

	for {

		msgChan := *p.tx.Load()

		// process new sends / listen for acks
		select {
		case msg := <-msgChan:
			metrics.SetGaugeWithLabels(outboundQueueLengthGauge, float32(len(msgChan)), p.labels)

			// Check if channel was closed; if so, ignore.
			if msg == nil {
				continue
			}
			metrics.IncrCounterWithLabels(sendCounter, 1, p.labels)

			switch msg.Inner.(type) {
			case *pb.PeerMessage_Syn, *pb.PeerMessage_Synack:
				// bump our epoch, reset num to 0
				currentSeqno = currentSeqno.nextEpoch()
				metrics.IncrCounterWithLabels(epochCounter, 1, p.labels)

				// drop our pending queue (should be for previous epoch)
				// Note: if this is a Syn, it's possible we have a pending Rst to the remote
				// peer, and it could get dropped. This is fine though because we already know
				// a Syn is going (we're sending it right now)
				p.pending = nil
			}

			logger.Debugw("got peermessage from enclave to send to peer",
				"seqno", currentSeqno,
				"type", fmt.Sprintf("%T", msg.Inner))

			pcd := pb.PeerConnectionData{
				Msg:   msg,
				Seqno: currentSeqno.proto(),
			}
			currentSeqno = currentSeqno.next()

			// send the message and save it for later resending
			p.pending = append(p.pending, &pcd)
			err := writeFramed(conn, &pb.PeerConnectionMessage{Inner: &pb.PeerConnectionMessage_Data{Data: &pcd}})
			if err != nil {
				return fmt.Errorf("send data: %w", err)
			}
		case ack := <-ackChan:
			if ack.err != nil {
				return ack.err
			}
			metrics.IncrCounterWithLabels(ackCounter, 1, p.labels)
			logger.Debugw("got ack from peer", "seqno", ack.ack)
			// dispose of everything we know has been acked by the peer
			if err := p.processAck(ack.ack); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
