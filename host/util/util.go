// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package util contains general purpose utilities
package util

import (
	"context"
	"time"

	"golang.org/x/exp/constraints"
)

// Min returns the minimum of a and b
func Min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of a and b
func Max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// Clamp restricts the value to the range [lo, hi]
func Clamp[T constraints.Ordered](v, lo, hi T) T {
	return Max(lo, Min(hi, v))
}

// RetryWithBackoff repeatedly attempts to call `fun`, increasing the wait between each call
func RetryWithBackoff(ctx context.Context, fun func() error, minSleep time.Duration, maxSleep time.Duration) error {
	_, err := RetrySupplierWithBackoff(ctx, func() (interface{}, error) { return nil, fun() }, minSleep, maxSleep)
	return err
}

// RetrySupplierWithBackoff repeatedly attempts to call `fun` to produce a value, increasing the wait between each call
func RetrySupplierWithBackoff[T any](ctx context.Context, fun func() (T, error), minSleep time.Duration, maxSleep time.Duration) (T, error) {
	sleepTime := time.Duration(0)
	var res T
	var err error
	for {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(sleepTime):
		}
		res, err = fun()
		if err == nil {
			return res, nil
		}
		sleepTime = Clamp(sleepTime*2, minSleep, maxSleep)
	}
}
