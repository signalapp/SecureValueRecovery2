// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/signalapp/svr2/util"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v2"
)

type Config struct {
	// See zap.Config
	Log *zap.Config `yaml:"log"`
	// Address for the peer server to listen on (ex 10.0.0.1:1234)
	PeerAddr string `yaml:"peerAddr"`
	// Address for http client server to listen on
	ClientListenAddr string `yaml:"clientListenAddr"`
	// Address for http control server to listen on
	ControlListenAddr string `yaml:"controlListenAddr"`
	// Configuration for redis cluster
	Redis RedisConfig `yaml:"redis"`
	// HTTP endpoint rate limits
	Limit RateLimitConfig `yaml:"limit"`
	// Host specific Raft configuration
	Raft RaftHostConfig `yaml:"raft"`
	// Peer protocol configuration
	Peer PeerConfig `yaml:"peer"`
	// The MRENCLAVE this host serves
	EnclaveID string `yaml:"enclaveId"`
	// Address to reach a datadog compatible statsd
	DatadogAgentHost string `yaml:"datadogAgentHost"`
	// TTL of initial Redis peerdb entry.
	InitialRedisPeerDBTTL time.Duration `yaml:"initialRedisPeerDBTTL"`
	// TTL of recurring Redis peerdb entry.
	RecurringRedisPeerDBTTL time.Duration `yaml:"recurringRedisPeerDBTTL"`
	// Configuration for the client websocket handler
	Request RequestConfig `yaml:"request"`
	// Periodicity/timeout for local liveness checks
	LocalLivenessCheckPeriod  time.Duration `yaml:"localLivenessCheckPeriod"`
	LocalLivenessCheckTimeout time.Duration `yaml:"localLivenessCheckTimeout"`
}

// validate returns a list of validation errors, or empty if there are no errors.
type validator interface{ validate() []string }

func (c *Config) validate() error {
	validators := []validator{&c.Raft, &c.Redis, &c.Limit, &c.Request}
	var errs []string
	for _, validator := range validators {
		errs = append(errs, validator.validate()...)
	}
	if len(errs) != 0 {
		return fmt.Errorf("invalid config: %v", strings.Join(errs, ","))
	}
	return nil
}

// Read parses the yaml file at the provided path into a Config
func Read(path string) (*Config, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	withenv := []byte(os.ExpandEnv(string(bs)))
	c, err := unmarshal(withenv)
	if err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func unmarshal(bs []byte) (*Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(bs, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Default provides reasonable default parameters that may be overridden by a config file
func Default() *Config {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:       true,
		Encoding:          "console",
		EncoderConfig:     encoderConfig,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
		DisableStacktrace: true,
	}

	return &Config{
		Log:               &config,
		PeerAddr:          "localhost:9000",
		ClientListenAddr:  "localhost:8080",
		ControlListenAddr: "localhost:8081",
		Raft: RaftHostConfig{
			RefreshStatusDuration:      time.Minute,
			TickDuration:               time.Second,
			MetricPollDuration:         time.Second * 10,
			EnvStatsPollDuration:       0,
			RefreshAttestationDuration: time.Minute * 10,
			EnclaveConcurrency:         util.Min(runtime.NumCPU(), 64),
		},
		Redis: RedisConfig{
			Name:             "test",
			MinSleepDuration: time.Second,
			MaxSleepDuration: time.Second * 30,
			Addrs:            []string{"localhost:6379"},
		},
		Limit: RateLimitConfig{
			BucketSize:       10,
			LeakRateScalar:   10,
			LeakRateDuration: time.Minute,
		},
		Peer: PeerConfig{
			MinSleepDuration: time.Millisecond * 10,
			MaxSleepDuration: time.Minute,
			AbandonDuration:  time.Minute * 10,
			BufferSize:       10_000,
		},
		Request: RequestConfig{
			WebsocketHandshakeTimeout: time.Second * 30,
			SocketTimeout:             time.Second * 30,
		},
		EnclaveID:                 "enclave",
		InitialRedisPeerDBTTL:     time.Minute * 120,
		RecurringRedisPeerDBTTL:   time.Minute * 5,
		LocalLivenessCheckPeriod:  time.Minute,
		LocalLivenessCheckTimeout: time.Minute,
	}
}
