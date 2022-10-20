// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"time"
)

type RedisConfig struct {
	// A seed list of host:port addresses of cluster nodes.
	Addrs []string `yaml:"addrs"`
	// password for instance (may be blank if protected mode is disabled)
	Password string `yaml:"password"`
	// a unique name for the deployment
	Name string `yaml:"name"`
	// minimum time to sleep for exponential backoff retries to redis
	MinSleepDuration time.Duration `yaml:"minSleepDuration"`
	// maximum time to sleep for exponential backoff retries to redis
	MaxSleepDuration time.Duration `yaml:"maxSleepDuration"`
}

func (r *RedisConfig) validate() []string {
	var errs []string
	if len(r.Addrs) == 0 {
		errs = append(errs, fmt.Sprintf("must provide redis Addrs"))
	}
	for _, addr := range r.Addrs {
		spl := strings.Split(addr, ":")
		if len(spl) != 2 {
			errs = append(errs, fmt.Sprintf("invalid redis Addr %v", addr))
		}
	}
	return errs
}
