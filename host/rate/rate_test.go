// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package rate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/signalapp/svr2/config"
)

func testLimiter(t *testing.T, limitConfig config.RateLimitConfig) Limiter {
	cfg := config.Default()
	cfg.Limit = limitConfig
	s := miniredis.RunT(t)
	cfg.Redis.Addrs = []string{s.Addr()}
	return NewConfiguredLimiter(cfg)
}

func TestRedisLimiter(t *testing.T) {
	cfg := config.RateLimitConfig{
		BucketSize:       2,
		LeakRateScalar:   1,
		LeakRateDuration: 100 * time.Millisecond,
	}
	limiter := testLimiter(t, cfg)

	var count int
	var err error
	var exceeded ErrLimitExceeded

	// wait until we get a limit exceeded error
	for count = 0; !errors.As(err, &exceeded); count++ {
		err = limiter.Limit(context.Background(), "test1")
	}
	if count < 2 {
		t.Errorf("took %v limits, should be at least %v", count, cfg.BucketSize)
	}

	start := time.Now()

	// keep trying until we don't get limited
	for errors.As(err, &exceeded) {
		err = limiter.Limit(context.Background(), "test1")
		time.Sleep(cfg.LeakRateDuration / 10)
	}
	duration := time.Since(start)

	if err != nil {
		t.Error(err)
	}
	if duration > cfg.LeakRateDuration*2 {
		t.Errorf("took %v to get a permit, should only need %v", duration, cfg.LeakRateDuration)
	}
}

func TestRedisLimiterExhaust(t *testing.T) {
	limiter := testLimiter(t, config.RateLimitConfig{
		BucketSize:       10,
		LeakRateScalar:   1,
		LeakRateDuration: time.Hour,
	})
	for i := 0; i < 10; i++ {
		if err := limiter.Limit(context.Background(), "test1"); err != nil {
			t.Errorf("iter %v : %v", i, err)
		}
	}

	// 11th request should get rate limited
	var errExceed ErrLimitExceeded
	err := limiter.Limit(context.Background(), "test1")
	if !errors.As(err, &errExceed) {
		t.Fatalf("Limit(11)=%v, want %v", err, "ErrLimitExceeded")
	}
	if errExceed.RetryAfter < (time.Hour - 5*time.Second) {
		t.Fatalf("RetryAfter = %v, should be at least %v", errExceed.RetryAfter, time.Hour-5*time.Second)
	}
	if errExceed.RetryAfter > time.Hour {
		t.Fatalf("RetryAfter = %v, should be at most %v", errExceed.RetryAfter, time.Hour)
	}

	// unrelated key should be fine
	if err := limiter.Limit(context.Background(), "test2"); err != nil {
		t.Error(err)
	}
}
