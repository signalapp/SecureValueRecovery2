// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"time"
)

// Clock provides an interface for accessing the current time.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (r *realClock) Now() time.Time {
	return time.Now()
}

// RealClock returns a clock which uses time.Now.
var RealClock Clock = (*realClock)(nil)

// TestAt is a Clock that returns a set single point in time.
type TestAt time.Time

func (t TestAt) Now() time.Time {
	return time.Time(t)
}
