// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"time"
)

type PeerConfig struct {
	// minimum time to sleep for exponential backoff retries to connect to a peer
	MinSleepDuration time.Duration `yaml:"minSleepDuration"`
	// maximum time to sleep for exponential backoff retries to connect to a peer
	MaxSleepDuration time.Duration `yaml:"maxSleepDuration"`
	// maximum time to attempt to connect to a peer before giving up
	AbandonDuration time.Duration `yaml:"abandonDuration"`
	// maximum number of messages to buffer for sending to a peer
	BufferSize int `yaml:"bufferSize"`
}

func (p *PeerConfig) validate() []string {
	var errs []string
	if p.BufferSize < 1 {
		errs = append(errs, fmt.Sprintf("invalid BufferSize: %v", p.BufferSize))
	}
	if p.MinSleepDuration > p.MaxSleepDuration {
		errs = append(errs, fmt.Sprintf("MinSleep (%v) must be less than MaxSleep (%v)", p.MinSleepDuration, p.MaxSleepDuration))
	}
	return errs
}
