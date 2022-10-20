// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"fmt"
	"testing"
	"time"
)

func TestTestAt(t *testing.T) {
	now := time.Now()
	ta := TestAt(now)
	if got := ta.Now(); got != now {
		t.Errorf("TestAt.Now: got %v want %v", got, now)
	}
}

func TestRealClock(t *testing.T) {
	t1 := time.Now()
	time.Sleep(time.Millisecond * 10)
	v1 := RealClock.Now()
	time.Sleep(time.Millisecond * 10)
	t2 := time.Now()
	time.Sleep(time.Millisecond * 10)
	v2 := RealClock.Now()
	if !v1.After(t1) {
		t.Errorf("v1 (%v) before t1 (%v)", v1, t1)
	}
	if !t2.After(v1) {
		t.Errorf("t2 (%v) before v1 (%v)", t2, v1)
	}
	if !v2.After(t2) {
		t.Errorf("v2 (%v) before t2 (%v)", v2, t2)
	}
}

func ExampleTestAt() {
	clock := TestAt(time.Unix(123, 0))
	now := clock.Now()
	fmt.Print(now.Unix())
	// Output:
	// 123
}
