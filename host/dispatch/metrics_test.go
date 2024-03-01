// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package dispatch

import (
	"fmt"
	"math"
	"strings"
	"testing"

	pb "github.com/signalapp/svr2/proto"

	metrics "github.com/hashicorp/go-metrics"
)

type mockMetricsWriter struct {
	data map[string]float32
}

func flatkey(key []string, labels []metrics.Label) string {
	s := strings.Join(key, ".")
	for _, label := range labels {
		s += fmt.Sprintf("%v:%v", label.Name, label.Value)
	}
	return s
}

func (m *mockMetricsWriter) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	k := flatkey(key, labels)
	if v, exists := m.data[k]; !exists {
		m.data[k] = val
	} else {
		m.data[k] = v + val
	}
}

func (m *mockMetricsWriter) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	k := flatkey(key, labels)
	m.data[k] = val
}

func TestFindMetrics(t *testing.T) {
	m := metricsUpdater{
		writer:   &mockMetricsWriter{data: make(map[string]float32)},
		counters: make(map[string][]*pb.U64PB),
	}
	initial := []*pb.U64PB{
		{Name: "m1", Tags: map[string]string{"t1": "1"}, V: 1.0},
		{Name: "m1", Tags: map[string]string{"t1": "2"}, V: 2.0},
	}
	m.updateMetrics(&pb.MetricsPB{Counters: initial})

	prev := m.findPrevCounter(&pb.U64PB{Name: "m1", Tags: map[string]string{"t1": "1"}, V: 3.0})
	if prev == nil {
		t.Errorf("previous counter not found")
	}
	if prev != initial[0] {
		t.Errorf("findPrevCounter=%v, want %v", prev, initial[0])
	}

	prev = m.findPrevCounter(&pb.U64PB{Name: "m2", Tags: map[string]string{"t1": "1"}, V: 1.0})
	if prev != nil {
		t.Error("previous counter should not exist")
	}
}

func TestUpdateCounters(t *testing.T) {
	measurements := []*pb.U64PB{
		{Name: "c1", Tags: map[string]string{"t1": "1"}, V: 1.0},
		{Name: "c1", Tags: map[string]string{"t1": "2"}, V: 2.0},
		{Name: "c2", Tags: map[string]string{"t1": "1"}, V: 1.0},
	}

	type update struct {
		id *pb.U64PB
		v  uint64
	}

	tests := []struct {
		name     string
		update   update
		expected float32
	}{
		{"Existing_c1_t1:1", update{measurements[0], 2}, 2.0},
		{"Existing_c1_t1:2", update{measurements[1], 3}, 3.0},
		{"Existing_c2", update{measurements[2], 2}, 2.0},
		{"ExistingDecrement", update{measurements[1], 1}, 1.0},
		{"NewName", update{&pb.U64PB{Name: "c3"}, 5}, 5.0},
		{"NewTagValue", update{&pb.U64PB{Name: "c1", Tags: map[string]string{"t2": "3"}}, 5}, 5.0},
		{"NewTag", update{&pb.U64PB{Name: "c1", Tags: map[string]string{"t3": "3"}}, 5}, 5.0},
	}

	for _, tt := range tests {
		for _, typ := range []string{"counter", "gauge"} {

			name := fmt.Sprintf("%v_%v", typ, tt.name)

			t.Run(name, func(t *testing.T) {
				w := &mockMetricsWriter{data: make(map[string]float32)}
				m := metricsUpdater{
					writer:   w,
					counters: make(map[string][]*pb.U64PB),
				}

				// update with initial values, then the test update
				switch typ {
				case "counter":
					m.updateMetrics(&pb.MetricsPB{Counters: measurements})
					m.updateMetrics(&pb.MetricsPB{Counters: []*pb.U64PB{
						{Name: tt.update.id.Name, Tags: tt.update.id.Tags, V: tt.update.v},
					}})
				case "gauge":
					m.updateMetrics(&pb.MetricsPB{Gauges: measurements})
					m.updateMetrics(&pb.MetricsPB{Gauges: []*pb.U64PB{
						{Name: tt.update.id.Name, Tags: tt.update.id.Tags, V: tt.update.v},
					}})
				default:
					t.Fatal("invalid type")
				}

				got, exists := w.data[flatkey([]string{tt.update.id.Name}, m.toLabels(tt.update.id))]
				if !exists {
					t.Error("metric does not exist after update")
				}
				if math.Abs(float64(tt.expected-got)) > 0.001 {
					t.Errorf("update was %v, want %v", got, tt.expected)
				}
			})
		}
	}
}
