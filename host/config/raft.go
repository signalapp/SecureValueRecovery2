// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"time"
)

type RaftHostConfig struct {
	// how often to update the peerdb to let other peers know we're joinable
	RefreshStatusDuration time.Duration `yaml:"refreshStatusDuration"`
	// how often to fetch a fresh attestation in the enclave
	RefreshAttestationDuration time.Duration `yaml:"refreshAttestationDuration"`
	// how often to send a raft tick down to the enclave
	TickDuration time.Duration `yaml:"tickDuration"`
	// how often to poll metrics from the enclave
	MetricPollDuration time.Duration `yaml:"metricPollDuration"`
	// how often to update env stats (memory usage, etc)
	EnvStatsPollDuration time.Duration `yaml:"envStatsPollDuration"`
	// max number of in-flight enclave calls
	EnclaveConcurrency int `yaml:"enclaveConcurrency"`
}

func (r *RaftHostConfig) validate() []string {
	var errs []string
	if r.EnclaveConcurrency <= 1 {
		errs = append(errs, fmt.Sprintf("invalid EnclaveConcurrency: %v", r.EnclaveConcurrency))
	}
	if r.TickDuration <= 0 {
		errs = append(errs, fmt.Sprintf("invalid TickDuration: %v", r.TickDuration))
	}
	if r.RefreshAttestationDuration <= 0 {
		errs = append(errs, fmt.Sprintf("invalid RefreshAttestationDuration: %v", r.RefreshAttestationDuration))
	}
	return errs
}
