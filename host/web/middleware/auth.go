// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package middleware

import (
	"net/http"

	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/logger"
)

// AuthCheck wraps an http.Handler to check the request's BasicAuth using the provided authenticator
func AuthCheck(authenticator auth.Auth, inner http.Handler) http.Handler {
	return &authHandler{authenticator, inner}
}

type authHandler struct {
	authenticator auth.Auth
	inner         http.Handler
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, pass, _ := r.BasicAuth()
	if err := a.authenticator.Check(user, pass); err != nil {
		logger.Infow("basic auth failed", "err", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	a.inner.ServeHTTP(w, r)
}
