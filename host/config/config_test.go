// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestConfig(t *testing.T) {
	var yaml = `
log:
  level: info
raft:
  tickDuration: 1000ms
  metricPollDuration: 2h
redis:
  password: flUFFybuNNy
`
	conf, err := unmarshal([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if conf.Log.Level.Level() != zap.InfoLevel {
		t.Errorf("conf.level=%v, want %v", conf.Log.Level.Level(), zap.InfoLevel)
	}
	if conf.Log.Encoding != "console" {
		t.Errorf("conf.encoding=%v, want %v", conf.Log.Encoding, "console")
	}
	if conf.Raft.TickDuration != time.Second {
		t.Errorf("conf.raft.tickDuration=%v, want %v", conf.Raft.TickDuration, time.Second)
	}
	if conf.Raft.MetricPollDuration != 2*time.Hour {
		t.Errorf("conf.raft.metricPollDuration=%v, want %v", conf.Raft.MetricPollDuration, time.Hour*2)
	}
	if strings.Contains(fmt.Sprintf("%v", conf), "flUFFybuNNy") {
		t.Errorf("does not elide password in String")
	}
	if strings.Contains(fmt.Sprintf("%#v", conf), "flUFFybuNNy") {
		t.Errorf("does not elide password in GoString")
	}
}
