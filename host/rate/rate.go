// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package rate provides rate limiters that may be used to limit the
// number of operations performed during some time period.
package rate

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"github.com/signalapp/svr2/config"
)

// ErrLimitExceeded indicates that the requested permit exceeds
// the configured rate limit for the user. After waiting for
// RetryAfter, the same request should succeed
type ErrLimitExceeded struct{ RetryAfter time.Duration }

func (e ErrLimitExceeded) Error() string {
	return fmt.Sprintf("rate limit excceded, retry after : %v", e.RetryAfter)
}

type Limiter interface {
	// Limit checks and enforces the rate limit. Returns nil if the operation
	// may proceed, or ErrLimitExceeded if the operation would exceed the
	// rate limit. If the rate limit cannot be checked, a different error
	// may be returned.
	Limit(ctx context.Context, key string) error
}

// NewRedisLimiter returns a Limiter backed by redis
func NewRedisLimiter(cfg *config.Config) Limiter {
	return &redisLimiter{
		fmt.Sprintf("%s::leaky_bucket", cfg.Redis.Name),
		redis_rate.Limit{
			Rate:   cfg.Limit.LeakRateScalar,
			Burst:  cfg.Limit.BucketSize,
			Period: cfg.Limit.LeakRateDuration,
		},
		redis_rate.NewLimiter(redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    cfg.Redis.Addrs,
			Password: cfg.Redis.Password,
		}))}
}

type redisLimiter struct {
	prefix  string           // prefix for rate limit buckets
	limit   redis_rate.Limit // configured limit
	limiter *redis_rate.Limiter
}

func (r *redisLimiter) Limit(ctx context.Context, key string) error {
	res, err := r.limiter.Allow(ctx, r.redisKey(key), r.limit)
	if err != nil {
		return err
	}
	if res.Allowed <= 0 {
		return ErrLimitExceeded{res.RetryAfter}
	}
	return nil
}

func (r *redisLimiter) redisKey(userKey string) string {
	return fmt.Sprintf("%s::%s", r.prefix, userKey)
}

type alwaysAllow struct{}

func (r alwaysAllow) Limit(context.Context, string) error { return nil }

// AlwaysAllow provides a Limiter that will always allow callers through
var AlwaysAllow = Limiter(alwaysAllow{})
