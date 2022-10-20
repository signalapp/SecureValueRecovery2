// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"time"
)

type RateLimitConfig struct {
	// The maximum size of the leaky bucket. This is the maximum "burst" of requests that will be allowed
	BucketSize int `yaml:"bucketSize"`
	// The amount of requests that will be added (up to BucketSize) per LeakRateDuration
	LeakRateScalar int `yaml:"leakRateScalar"`
	// The period at which LeakRateScalar additional requests will be allowed
	LeakRateDuration time.Duration `yaml:"leakRateDuration"`
}

func (r *RateLimitConfig) validate() []string {
	var errs []string
	if r.BucketSize < 0 {
		errs = append(errs, fmt.Sprintf("invalid BucketSize: %v", r.BucketSize))
	}
	if r.LeakRateScalar < 0 {
		errs = append(errs, fmt.Sprintf("invalid LeakRateDuration: %v", r.LeakRateScalar))
	}
	return errs
}
