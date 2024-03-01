// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/hashicorp/go-metrics"
	"github.com/signalapp/svr2/util"
)

// Instrument wraps an http.Handler and updates metrics with the http response
func Instrument(inner http.Handler) http.Handler {
	return &handler{inner: inner}
}

type handler struct {
	inner http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ww := &writerWrapper{w: w}
	h.inner.ServeHTTP(ww, r)
	if ww.recorded {
		userAgent := r.UserAgent()
		labels := util.ParseTags(userAgent)
		labels = append(labels,
			metrics.Label{Name: "method", Value: r.Method},
			metrics.Label{Name: "endpoint", Value: r.URL.Path},
			metrics.Label{Name: "status", Value: strconv.Itoa(ww.statusCode)},
		)
		metrics.IncrCounterWithLabels([]string{"http", "response"}, 1, labels)
	}
}

// When a response is written, record the status code so it can be instrumented later
type writerWrapper struct {
	w          http.ResponseWriter
	statusCode int
	recorded   bool
}

var _ http.ResponseWriter = (*writerWrapper)(nil)
var _ http.Hijacker = (*writerWrapper)(nil)

func (ww *writerWrapper) Header() http.Header {
	return ww.w.Header()
}

func (ww *writerWrapper) Write(b []byte) (int, error) {
	if !ww.recorded {
		ww.recorded = true
		ww.statusCode = http.StatusOK
	}
	return ww.w.Write(b)
}

func (ww *writerWrapper) WriteHeader(statusCode int) {
	ww.recorded = true
	ww.statusCode = statusCode
	ww.w.WriteHeader(statusCode)
}

func (ww *writerWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := ww.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	if !ww.recorded {
		// If the response handler is switching protocols, (e.x. upgrading
		// to a websocket) report StatusSwitchingProtocols
		ww.recorded = true
		ww.statusCode = http.StatusSwitchingProtocols
	}
	return h.Hijack()
}
