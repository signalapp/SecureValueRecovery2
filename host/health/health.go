// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package health

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/signalapp/svr2/logger"
)

// Health wraps an error (nil means "healthy"), and provides HTTP handling
// logic to serve that error.
type Health struct {
	mu   sync.Mutex
	name string
	err  error
}

// New creates a new health object, with initial health set based on the
// 'initial' error (nil==healthy).
func New(name string, initial error) *Health {
	return &Health{name: name, err: initial}
}

// Set sets the underlying error for this Health object; err=nil means "OK"
func (h *Health) Set(err error) {
	h.mu.Lock()
	oldErr := h.err
	h.err = err
	h.mu.Unlock()
	if (err == nil) != (oldErr == nil) {
		logger.Infof("Setting health %q from [%v] -> [%v]", h.name, oldErr, err)
	}
}

// ServeHTTP implements http.Handler.
func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	err := h.err
	h.mu.Unlock()
	if err == nil {
		fmt.Fprintf(w, "ok")
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "error: %v", err)
}
