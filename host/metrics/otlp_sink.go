// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-metrics"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	metricSDK "go.opentelemetry.io/otel/sdk/metric"

	"github.com/signalapp/svr2/logger"
)

type OTLPSink struct {
	meter         metric.Meter
	meterProvider *metricSDK.MeterProvider
}

var _ metrics.ShutdownSink = (*OTLPSink)(nil)

// NewOTLPSink initializes the Open Telemetry metrics SDK and returns a new sink.
func NewOTLPSink(ctx context.Context) (*OTLPSink, error) {

	// this is a greatly condensed adaptation of
	// https://opentelemetry.io/docs/languages/go/getting-started/#initialize-the-opentelemetry-sdk
	metricExporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating new otlp meter exporter: %w", err)
	}
	meterProvider := metricSDK.NewMeterProvider(metricSDK.WithReader(metricSDK.NewPeriodicReader(metricExporter)))
	otel.SetMeterProvider(meterProvider)

	meter := otel.Meter(metrics.Default().ServiceName)
	return &OTLPSink{meter, meterProvider}, nil
}

func (s *OTLPSink) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	_ = s.meterProvider.Shutdown(ctx)
}

func (s *OTLPSink) SetGauge(key []string, val float32) {
	s.SetGaugeWithLabels(key, val, nil)
}

func (s *OTLPSink) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	g, err := s.meter.Float64Gauge(name(key))
	if err != nil {
		logger.Errorf("failed to record %s: %v", name(key), err)
		return
	}

	g.Record(context.Background(), float64(val), metric.WithAttributes(labelsToAttributes(labels)...))
}

// EmitKey is not implemented
func (s *OTLPSink) EmitKey(_ []string, _ float32) {
	logger.Errorf("EmitKey is not implemented")
}

func (s *OTLPSink) IncrCounter(key []string, val float32) {
	s.IncrCounterWithLabels(key, val, nil)
}

func (s *OTLPSink) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	c, err := s.meter.Float64Counter(name(key))
	if err != nil {
		logger.Errorf("failed to record %s: %v", name(key), err)
		return
	}

	c.Add(context.Background(), float64(val), metric.WithAttributes(labelsToAttributes(labels)...))
}

func (s *OTLPSink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (s *OTLPSink) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {
	h, err := s.meter.Float64Histogram(name(key))
	if err != nil {
		logger.Errorf("failed to record %s: %v", name(key), err)
		return
	}

	h.Record(context.Background(), float64(val), metric.WithAttributes(labelsToAttributes(labels)...))
}

func labelsToAttributes(labels []metrics.Label) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	for _, label := range labels {
		attrs = append(attrs, attribute.String(label.Name, label.Value))
	}

	return attrs
}

func name(key []string) string {
	return strings.Join(key, ".")
}
