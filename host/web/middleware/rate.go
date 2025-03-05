// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package middleware

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/hashicorp/go-metrics"

	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/rate"
)

// RateLimit wraps a http.Handler and enforces a rate limit on requests going to that handler
func RateLimit(limiter rate.Limiter, next http.Handler) http.Handler {
	return &rateLimitHandler{limiter, next}
}

type rateLimitHandler struct {
	limiter rate.Limiter
	inner   http.Handler
}

var (
	rateLimitCounter    = []string{"request", "rateLimit"}
	rateLimitErrCounter = []string{"request", "rateLimitErr"}
)

func (rh *rateLimitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, _, _ := r.BasicAuth()

	err := rh.limiter.Limit(r.Context(), user)
	var retryErr rate.ErrLimitExceeded
	rateLimitExceeded := errors.As(err, &retryErr)

	metrics.IncrCounterWithLabels(rateLimitCounter, 1, []metrics.Label{
		{Name: "exceeded", Value: strconv.FormatBool(rateLimitExceeded)},
	})

	if rateLimitExceeded {
		retryAfterSecs := int64(retryErr.RetryAfter.Seconds())
		w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSecs, 10))
		w.WriteHeader(http.StatusTooManyRequests)
		return
	} else if errors.Is(err, context.Canceled) {
		logger.Infow("context cancelled while updating rate limit", "err", err)
		w.WriteHeader(499)
		return
	} else if err != nil {
		// still allow request in the case where we can't access the rate limiter
		metrics.IncrCounter(rateLimitErrCounter, 1)
		logger.Errorw("could not update rate limit", "err", err)
	}
	rh.inner.ServeHTTP(w, r)
}
