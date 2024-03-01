// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package peer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"golang.org/x/sync/errgroup"

	metrics "github.com/hashicorp/go-metrics"
	pb "github.com/signalapp/svr2/proto"
)

// PeerServer implements the host to host communication protocol
//
// Clients send messages to the server that are routed to the server's local enclave.
// The PeerServer responds with acks only.
//
// Internally, PeerServer accepts new connections, identifies the initiating peer,
// and passes the connection to the appropriate peerReceiver responsible for that peer
type PeerServer struct {
	esender EnclaveSender
	me      peerid.PeerID
	eg      *errgroup.Group
	ctx     context.Context

	receiversMu sync.Mutex
	receivers   map[peerid.PeerID]*peerReceiver
}

// NewPeerServer creates a new peer server which must be started with Listen
func NewPeerServer(ctx context.Context, me peerid.PeerID, enclaveSender EnclaveSender) *PeerServer {
	eg, ctx := errgroup.WithContext(ctx)
	return &PeerServer{
		esender:   enclaveSender,
		me:        me,
		receivers: make(map[peerid.PeerID]*peerReceiver),
		eg:        eg,
		ctx:       ctx,
	}
}

var (
	connectCounter    = []string{"peer", "server", "connect"}
	activeClientGauge = []string{"peer", "server", "activeClients"}
	reconnectCounter  = []string{"peer", "server", "reconnect"}
	disconnectCounter = []string{"peer", "server", "disconnect"}
	receiveCounter    = []string{"peer", "server", "receive"}
)

// Listen for new connections on addr
//
// Returns only after cancellation or a fatal error is encountered. Listen takes ownership
// of calling Close on the provided net.Listener
func (p *PeerServer) Listen(ln net.Listener) error {

	p.eg.Go(func() error {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}

			metrics.IncrCounter(connectCounter, 1)
			p.eg.Go(func() error {
				p.handleConnection(conn)
				return nil
			})
		}
	})
	<-p.ctx.Done()
	// stop the listener so accept unblocks
	ln.Close()
	return p.eg.Wait()
}

// handleConnection initiates the peer handshake, and then hands-off the
// connection to a peerReceiver
//
// If this is the first connection for a peerID, the receiver is created,
// otherwise the receiver is just notified of the new connection
func (p *PeerServer) handleConnection(conn net.Conn) {
	reader := bufio.NewReader(conn)
	them, us, err := readHello(reader)
	if err != nil {
		logger.Warnw("failed to read hello from client",
			"peer", conn.RemoteAddr(),
			"err", err)
		conn.Close()
		return
	}
	if us != p.me {
		logger.Warnw("got incorrect peer ID", "peer", conn.RemoteAddr(), "peerID", them)
		conn.Close()
		return
	}

	logger.Infow("received connect attempt from peer", "peer", conn.RemoteAddr(), "peerID", them)

	// notify the receiver that it should switch over to this connection (replacing
	// any existing connection). Note that it's still possible this kicks off after we've
	// been cancelled -- nbd, the receiveLoop will bail out immediately
	select {
	case <-p.ctx.Done():
		conn.Close()
	case p.getOrCreate(them).conns <- conn:
	}
}

// getOrCreate looks up the peerReceiver, creating one if it doesn't exist
func (p *PeerServer) getOrCreate(them peerid.PeerID) *peerReceiver {
	p.receiversMu.Lock()
	defer p.receiversMu.Unlock()

	receiver, ok := p.receivers[them]
	if !ok {
		metrics.SetGauge(activeClientGauge, float32(len(p.receivers)))
		logger.Infow("received first connect from peer", "peerID", them)
		// first connection from this peer,
		// create a receiver and start it
		receiver = &peerReceiver{
			local:   p.me,
			remote:  them,
			esender: p.esender,
			conns:   make(chan net.Conn)}
		p.receivers[them] = receiver
		p.eg.Go(func() error { return receiver.receiveLoop(p.ctx) })
	}
	return receiver

}

// peerReceiver handles inbound messages
// from a single remote peerID
//
// Only a single connection is allowed,
// and on a reconnect from the same peer
// the previous connection is first shutdown
type peerReceiver struct {
	seqno   sequenceNumber // The sequence number of the last message received
	conns   chan net.Conn  // Newly accepted connections for this peerID
	local   peerid.PeerID
	remote  peerid.PeerID
	esender EnclaveSender
}

// updateSeqno updates the sequence number after a message is received
//
// Returns true if the sequence number is new
// Returns an error if the sequence number is invalid to see
// in the current state
func (p *peerReceiver) updateSeqno(seqno sequenceNumber) (bool, error) {
	if seqno.cmp(p.seqno) <= 0 {
		return false, nil
	}
	if !seqno.follows(p.seqno) {
		return false, fmt.Errorf("expected message seqno=%v, got %v", p.seqno.next(), seqno)
	}
	p.seqno = seqno
	return true, nil
}

// receiveLoop spins up a handler for inbound connections, cancelling and
// replacing the existing handler if a peer reconnects
//
// runs until it is cancelled
func (p *peerReceiver) receiveLoop(ctx context.Context) error {
	labels := []metrics.Label{{Name: "peerID", Value: p.remote.String()}}
	done := make(chan error, 1)
	var lastConn net.Conn
	for {
		select {
		case <-ctx.Done():
			// cancelled, stop the conn handler
			if lastConn != nil {
				lastConn.Close() // close the current connection
				<-done           // wait until done (ignore error we probably caused)
			}
			return ctx.Err()
		case conn := <-p.conns:
			// the same peer reconnected, replace the conn handler
			if lastConn != nil {
				metrics.IncrCounterWithLabels(reconnectCounter, 1, labels)
				logger.Infow("peer client reconnected",
					"peer_id", p.remote,
					"peer", lastConn.RemoteAddr(),
				)
				lastConn.Close() // close the current connection
				<-done           // wait until done (ignore error we probably caused)
			}
			lastConn = conn

			// spin up handler for new connection
			go func() { done <- p.handleConnection(conn) }()
		case err := <-done:
			metrics.IncrCounterWithLabels(disconnectCounter, 1, labels)
			// finished without an external connection close,
			// log and wait for the next connect
			logger.Warnw("error in receive handler",
				"err", err,
				"peer_id", p.remote,
				"peer", lastConn.RemoteAddr())
			lastConn = nil
		}
	}
}

func (p *peerReceiver) handleConnection(conn net.Conn) error {
	defer conn.Close()

	logger.Debugw("sending helloAck to peer",
		"seqno", p.seqno,
		"peerID", p.remote,
		"peer", conn.RemoteAddr(),
	)
	peerLabel := metrics.Label{Name: "peerID", Value: p.remote.String()}

	// Before getting to this handler, we should have read
	// the peer's initial hello. Now respond with our current
	// sequence number so the client knows where to start sending
	if err := writeHelloAck(conn, p.seqno); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)

	// the server read loop
	// 1. read a request from the client
	// 2. update our latest sequence number
	// 3. if this a new request, forward it to the enclave
	// 4. write an ack back to the client
	// 5. repeat
	for {
		// read message from client
		pcm, err := readFramed(reader)
		if err != nil {
			return fmt.Errorf("read data: %w", err)
		}

		msg, ok := pcm.Inner.(*pb.PeerConnectionMessage_Data)
		if !ok {
			// log and ignore, might be a message we don't know about
			logger.Errorw("Received unknown message",
				"peer", conn.RemoteAddr(),
				"peerID", p.remote,
			)
			continue
		}

		msgSeqno, err := makeSeqno(msg.Data.Seqno)
		if err != nil {
			return err
		}
		isNew, err := p.updateSeqno(msgSeqno)
		if err != nil {
			return err
		}

		metrics.IncrCounterWithLabels(receiveCounter, 1, []metrics.Label{
			{Name: "duplicate", Value: strconv.FormatBool(!isNew)},
			peerLabel,
		})

		if !isNew {
			// we've already delievered this message
			if err := writeAck(conn, p.seqno); err != nil {
				return err
			}
			continue
		}

		// this is a new message, forward it to enclave
		u := pb.UntrustedMessage{
			Inner: &pb.UntrustedMessage_PeerMessage{
				PeerMessage: &pb.PeerMessage{
					PeerId: p.remote[:],
					Inner:  msg.Data.Msg.Inner,
				},
			},
		}

		logger.Debugw("received new message from peer, forwarding to enclave",
			"peer", conn.RemoteAddr(),
			"peerID", p.remote,
			"seqno", msgSeqno,
			"type", fmt.Sprintf("%T", msg.Data.Msg.Inner),
		)

		// It is required that we do not send into the enclave
		// with any concurrency. We must wait for the previous message
		// from a peer to be processed before sending a new one
		if _, err := p.esender.Send(&u); err != nil {
			return err
		}
		if err := writeAck(conn, msgSeqno); err != nil {
			return err
		}
	}
}
