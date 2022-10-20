// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"time"
)

type RequestConfig struct {
	// Timeout to perform websocket handshake over http connection
	WebsocketHandshakeTimeout time.Duration `yaml:"socketTimeout"`

	// Timeout for websocket read/write operations
	SocketTimeout time.Duration `yaml:"socketTimeout"`
}

func (r *RequestConfig) validate() []string {
	var errs []string
	if r.WebsocketHandshakeTimeout <= 0 {
		errs = append(errs, fmt.Sprintf("Handshake timeout %v must be >0", r.WebsocketHandshakeTimeout))
	}
	if r.SocketTimeout <= 0 {
		errs = append(errs, fmt.Sprintf("Socket timeout %v must be >0", r.SocketTimeout))
	}
	return errs
}
