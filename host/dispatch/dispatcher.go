// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"github.com/signalapp/svr2/util"
	"golang.org/x/sync/errgroup"

	metrics "github.com/armon/go-metrics"
	pb "github.com/signalapp/svr2/proto"
)

type txid uint64

type EnclaveSender interface {
	// SendMessage sends a message to the running enclave.
	SendMessage(msgPB *pb.UntrustedMessage) error
}

type PeerSender interface {
	// Send sends a message to a remote peer
	Send(msg *pb.PeerMessage) error
}

// Dispatcher routes messages between host and
// enclave, associating requests and replies
type Dispatcher struct {
	enclave EnclaveSender
	// generate unique request ids
	txGen *util.TxGenerator
	// messages to send to enclave
	tx chan *toEnclave
	// messages received from enclave
	rx <-chan *pb.EnclaveMessage
	// updated with enclave metrics
	metricsUpdater *metricsUpdater
	// receivers represents requests from the host waiting for a reply
	receiversMu sync.Mutex
	receivers   map[txid]chan *pb.EnclaveMessage
	// configuration
	cfg config.RaftHostConfig
}

var (
	ErrEnclaveClosed = errors.New("server: Enclave closed")

	tickCounterName               = []string{"dispatcher", "ticks"}
	processMessageCounterName     = []string{"dispatcher", "processMessage"}
	peerReconnectCounterName      = []string{"dispatcher", "manualPeerReconnect"}
	refreshAttestationCounterName = []string{"dispatcher", "refreshAttestation"}
)

type toEnclave struct {
	// message to send to enclave
	message *pb.UntrustedMessage
	// channel on which to receive a reply
	recv chan *pb.EnclaveMessage
}

// New creates a dispatcher which sends messages to
// the provided enclave, and receives messages from the enclave on rx
func New(cfg config.RaftHostConfig, txGen *util.TxGenerator, e EnclaveSender, rx <-chan *pb.EnclaveMessage) *Dispatcher {
	return &Dispatcher{
		enclave:        e,
		txGen:          txGen,
		receivers:      make(map[txid]chan *pb.EnclaveMessage),
		tx:             make(chan *toEnclave),
		rx:             rx,
		metricsUpdater: newMetricsUpdater(),
		cfg:            cfg,
	}
}

// Send sends a message to the enclave and potentially wait for a reply. If p is a message
// that requires no reply, Send will still block until the enclave has processed the message
// and this method will return nil.
func (d *Dispatcher) Send(p *pb.UntrustedMessage) (*pb.EnclaveMessage, error) {
	recv := make(chan *pb.EnclaveMessage, 1)
	d.tx <- &toEnclave{p, recv}
	response := <-recv
	if _, expectReply := p.Inner.(*pb.UntrustedMessage_H2ERequest); response == nil && expectReply {
		// we expected a response but got a closed channel
		return nil, errors.New("failed to get enclave response")
	}
	return response, nil
}

// SendTransaction is like [Send] but for requests to the enclave that expect a response
// The provided request should not be tagged with a RequestID, this will be handled internally
func (d *Dispatcher) SendTransaction(req *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error) {
	if req.RequestId != 0 {
		return nil, errors.New("illegal SendTransaction : should not provide a request id")
	}
	req.RequestId = d.txGen.NextID()
	wrappedResp, err := d.Send(&pb.UntrustedMessage{Inner: &pb.UntrustedMessage_H2ERequest{
		H2ERequest: req,
	}})
	if err != nil {
		return nil, err
	}
	reply, ok := wrappedResp.Inner.(*pb.EnclaveMessage_H2EResponse)
	if !ok {
		return nil, errors.New("unexpected response type from enclave")
	}
	return reply.H2EResponse, nil
}

// Run runs the dispatcher process until cancelled or encountering a fatal error
func (d *Dispatcher) Run(ctx context.Context, peerSender PeerSender) error {
	grp, ctx := errgroup.WithContext(ctx)
	grp.Go(func() error { return d.forwardToEnclaveLoop(ctx) })
	grp.Go(func() error { return d.forwardToHostLoop(ctx, peerSender) })
	grp.Go(func() error { return d.tickLoop(ctx) })
	grp.Go(func() error { return d.metricLoop(ctx) })
	grp.Go(func() error { return d.refreshAttestationLoop(ctx) })
	err := grp.Wait()

	return err
}

// forwardToEnclaveLoop takes messages receieved via Send and forwards them to the enclave
func (d *Dispatcher) forwardToEnclaveLoop(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	// Rather than let it compete with host originated message sends, one of our concurrency
	// permits is reserved for our tick thread. This ensures ticks run in a timely fashion.
	enclaveConcurrency := d.cfg.EnclaveConcurrency - 1

	for i := 0; i < enclaveConcurrency; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case toEnclave := <-d.tx:
					if err := d.forwardToEnclave(toEnclave); err != nil {
						logger.Errorw("failed to send message to enclave", "err", err)
					}
				}
			}
		})
	}
	return eg.Wait()
}

// forwardToEnclaveLoop takes messages receieved from the enclave and forwards them to the host
func (d *Dispatcher) forwardToHostLoop(ctx context.Context, peerSender PeerSender) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case fromEnclave := <-d.rx:
			if fromEnclave == nil {
				return ErrEnclaveClosed
			}
			if err := d.forwardToHost(peerSender, fromEnclave); err != nil {
				logger.Errorw("dropping enclave message", "err", err)
			}
		}
	}
}

// tickLoop sends tick messages to the enclave on a fixed interval
func (d *Dispatcher) tickLoop(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.TickDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			tick := pb.UntrustedMessage{Inner: &pb.UntrustedMessage_TimerTick{TimerTick: &pb.TimerTick{NewTimestampUnixSecs: uint64(time.Now().Unix())}}}
			if err := d.enclave.SendMessage(&tick); err != nil {
				return err
			}
			metrics.IncrCounter(tickCounterName, 1)
		}
	}
}

// refreshAttestationLoop sends RefreshAttestation messages to the enclave on a fixed interval
func (d *Dispatcher) refreshAttestationLoop(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.RefreshAttestationDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.refreshAttestation(); err != nil {
				return err
			}
		}
	}
}

func (d *Dispatcher) refreshAttestation() error {
	resp, err := d.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_RefreshAttestation{
			RefreshAttestation: &pb.RefreshAttestation{RotateClientKey: true},
		},
	})
	if err != nil {
		return err
	}
	v, ok := resp.Inner.(*pb.HostToEnclaveResponse_Status)
	if !ok {
		return fmt.Errorf("unexpected response from enclave %v", resp)
	}
	if v.Status != pb.Error_OK {
		logger.Warnw("failed to refresh attestation", "err", v.Status)
	}
	metrics.IncrCounterWithLabels(refreshAttestationCounterName, 1, []metrics.Label{
		{Name: "success", Value: strconv.FormatBool(v.Status == pb.Error_OK)},
	})
	return nil
}

// metricLoop sends requests for metrics to the enclave on a fixed interval
func (d *Dispatcher) metricLoop(ctx context.Context) error {
	poller := time.NewTicker(d.cfg.MetricPollDuration)
	var lastEnvStats time.Time
	defer poller.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poller.C:
			// First get status, since it might reset base labels.
			resp, err := d.SendTransaction(&pb.HostToEnclaveRequest{
				Inner: &pb.HostToEnclaveRequest_GetEnclaveStatus{GetEnclaveStatus: true},
			})
			if err != nil {
				return err
			}
			switch v := resp.Inner.(type) {
			case *pb.HostToEnclaveResponse_GetEnclaveStatusReply:
				d.metricsUpdater.updateStatus(v.GetEnclaveStatusReply)
			case *pb.HostToEnclaveResponse_Status:
				logger.Warnf("failed to poll status from enclave", "err", v.Status.String())
			default:
				return errors.New("unexpected HostToEnclaveResponse from enclave")
			}
			// Then, get actual metrics.
			req := &pb.HostToEnclaveRequest{}
			// TODO: after we stop supporting older versions, just use HostToEnclaveRequest_Metrics with UpdateEnvStats set correctly.
			if lastEnvStats.Add(d.cfg.EnvStatsPollDuration).Before(time.Now()) {
				lastEnvStats = time.Now()
				req.Inner = &pb.HostToEnclaveRequest_RequestMetrics{RequestMetrics: true}
			} else {
				req.Inner = &pb.HostToEnclaveRequest_Metrics{Metrics: &pb.MetricsRequest{UpdateEnvStats: false}}
			}
			resp, err = d.SendTransaction(req)
			if err != nil {
				return err
			}
			switch v := resp.Inner.(type) {
			case *pb.HostToEnclaveResponse_MetricsReply:
				d.metricsUpdater.updateMetrics(v.MetricsReply)
			case *pb.HostToEnclaveResponse_Status:
				logger.Warnf("failed to poll metrics from enclave", "err", v.Status.String())
			default:
				return errors.New("unexpected HostToEnclaveResponse from enclave")
			}
		}
	}
}

func (d *Dispatcher) forwardToEnclave(toEnclave *toEnclave) error {
	metrics.IncrCounterWithLabels(processMessageCounterName, 1, []metrics.Label{{Name: "destination", Value: "enclave"}})
	p := toEnclave.message
	request, expectReply := p.Inner.(*pb.UntrustedMessage_H2ERequest)

	if !expectReply {
		// host does not expect a reply, fire and forget
		err := d.enclave.SendMessage(toEnclave.message)
		close(toEnclave.recv)
		return err
	}

	d.setReceiver(txid(request.H2ERequest.RequestId), toEnclave.recv)
	if err := d.enclave.SendMessage(toEnclave.message); err != nil {
		if c := d.deleteReceiver(txid(request.H2ERequest.RequestId)); c != nil {
			close(c)
		}
		return err
	}
	return nil
}

func (d *Dispatcher) forwardToHost(peerSender PeerSender, message *pb.EnclaveMessage) error {
	switch v := message.Inner.(type) {
	case *pb.EnclaveMessage_H2EResponse:
		metrics.IncrCounterWithLabels(processMessageCounterName, 1, []metrics.Label{{Name: "destination", Value: "host"}})
		id := txid(v.H2EResponse.RequestId)
		recv := d.deleteReceiver(id)
		if recv == nil {
			return fmt.Errorf("response %v has no associated request", message)
		}
		recv <- message
		close(recv)
	case *pb.EnclaveMessage_PeerMessage:
		metrics.IncrCounterWithLabels(processMessageCounterName, 1, []metrics.Label{{Name: "destination", Value: "peer"}})
		if err := peerSender.Send(v.PeerMessage); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) ResetPeer(peerID peerid.PeerID) error {
	logger.Infow("resetting peer", "peerID", peerID)
	_, err := d.Send(&pb.UntrustedMessage{
		Inner: &pb.UntrustedMessage_ResetPeer{
			ResetPeer: &pb.EnclavePeer{
				PeerId: peerID[:],
			},
		},
	})
	if err != nil {
		logger.Errorw("failed to reset peer connection", "peerID", peerID, "err", err)
	}
	metrics.IncrCounterWithLabels(peerReconnectCounterName, 1, []metrics.Label{{Name: "success", Value: strconv.FormatBool(err == nil)}})
	return err
}

func (d *Dispatcher) getReceiver(id txid) (recv chan *pb.EnclaveMessage, exists bool) {
	d.receiversMu.Lock()
	defer d.receiversMu.Unlock()
	recv, exists = d.receivers[id]
	return
}

func (d *Dispatcher) setReceiver(id txid, recv chan *pb.EnclaveMessage) {
	d.receiversMu.Lock()
	defer d.receiversMu.Unlock()
	d.receivers[id] = recv
}

func (d *Dispatcher) deleteReceiver(id txid) chan *pb.EnclaveMessage {
	d.receiversMu.Lock()
	defer d.receiversMu.Unlock()
	out := d.receivers[id]
	delete(d.receivers, id)
	return out
}
