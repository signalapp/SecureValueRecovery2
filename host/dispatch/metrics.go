// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package dispatch

import (
	"github.com/google/go-cmp/cmp"
	"github.com/signalapp/svr2/peerid"

	metrics "github.com/armon/go-metrics"
	pb "github.com/signalapp/svr2/proto"
)

type metricsWriter interface {
	IncrCounterWithLabels(key []string, val float32, labels []metrics.Label)
	SetGaugeWithLabels(key []string, val float32, labels []metrics.Label)
}

// metricsUpdater converts polled enclave metric protobufs into metrics updates
type metricsUpdater struct {
	writer     metricsWriter
	counters   map[string][]*pb.U64PB
	baseLabels []metrics.Label
}

func newMetricsUpdater() *metricsUpdater {
	return &metricsUpdater{
		writer:     metrics.Default(),
		counters:   make(map[string][]*pb.U64PB),
		baseLabels: make([]metrics.Label, 0, 16),
	}
}

// findPrevCounter returns the last value seen for the provided counter
func (m *metricsUpdater) findPrevCounter(counter *pb.U64PB) *pb.U64PB {
	prev, exists := m.counters[counter.Name]
	if !exists {
		return nil
	}
	for _, c := range prev {
		if cmp.Equal(c.Tags, counter.Tags) {
			return c
		}
	}
	return nil
}

// updateMetrics updates the underlying metrics using the current enclave metrics snapshot. Because
// enclave counters are the counter's current state, the previous snapshot is stored and the diff
// between the current snapshot and the previous snapshot is calculated.
func (m *metricsUpdater) updateMetrics(metricsPB *pb.MetricsPB) {
	for _, gauge := range metricsPB.Gauges {
		m.writer.SetGaugeWithLabels([]string{gauge.Name}, float32(gauge.V), m.toLabels(gauge))
	}
	for _, counter := range metricsPB.Counters {
		prev := m.findPrevCounter(counter)
		if prev == nil {
			m.writer.IncrCounterWithLabels([]string{counter.Name}, float32(counter.V), m.toLabels(counter))
		} else {
			diff := int64(counter.V - prev.V)
			m.writer.IncrCounterWithLabels([]string{counter.Name}, float32(diff), m.toLabels(counter))
		}
	}

	for name, counters := range m.counters {
		m.counters[name] = counters[:0]
	}
	for _, counter := range metricsPB.Counters {
		m.counters[counter.Name] = append(m.counters[counter.Name], counter)
	}
}

var (
	peerState         = []string{"peer", "state"}
	peerAttestationTs = []string{"peer", "last_attestation_unix_secs"}
	peerNextIdx       = []string{"peer", "next_idx"}
	peerMatchIdx      = []string{"peer", "match_idx"}
	peerInflightIdx   = []string{"peer", "inflight_idx"}
)

func raftStatus(s *pb.EnclavePeerStatus) string {
	switch {
	case s.IsLeader:
		return "leader"
	case s.IsVoting:
		return "voter"
	case s.InRaft:
		return "nonvoter"
	default:
		return "nonmember"
	}
}

func (m *metricsUpdater) updateStatus(s *pb.EnclaveReplicaStatus) {
	for _, peer := range s.Peers {
		if peer.Me {
			m.baseLabels = m.baseLabels[:0]
			m.baseLabels = append(m.baseLabels, metrics.Label{Name: "raft", Value: raftStatus(peer)})
			if id, err := peerid.Make(peer.PeerId); err == nil {
				m.baseLabels = append(m.baseLabels, metrics.Label{Name: "myid", Value: id.String()})
			}
			break
		}
	}
	for _, peer := range s.Peers {
		id, err := peerid.Make(peer.PeerId)
		if err != nil || peer.Me {
			continue
		}
		lbls := append(m.baseLabels, metrics.Label{Name: "peerid", Value: id.String()})
		m.writer.SetGaugeWithLabels(peerState, float32(peer.GetConnectionStatus().GetState()), lbls)
		if peer.InRaft {
			m.writer.SetGaugeWithLabels(peerAttestationTs, float32(peer.GetConnectionStatus().GetLastAttestationUnixSecs()), lbls)
			if peer.ReplicationStatus != nil {
				m.writer.SetGaugeWithLabels(peerNextIdx, float32(peer.ReplicationStatus.NextIndex), lbls)
				m.writer.SetGaugeWithLabels(peerMatchIdx, float32(peer.ReplicationStatus.MatchIndex), lbls)
				m.writer.SetGaugeWithLabels(peerInflightIdx, float32(peer.ReplicationStatus.InflightIndex), lbls)
			}
		}
	}
}

// toLabels extracts metrics.Labels from tags on a metrics proto
func (m *metricsUpdater) toLabels(metric *pb.U64PB) []metrics.Label {
	labels := m.baseLabels
	for k, v := range metric.Tags {
		labels = append(labels, metrics.Label{
			Name:  k,
			Value: v,
		})
	}
	return labels
}
