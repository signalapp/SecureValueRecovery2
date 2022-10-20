// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package auth provides for the ability to authenticate clients using
// basic auth credentials they get from Signal chat servers'
// ExternalServiceCredentialsGenerator.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/signalapp/svr2/util"
)

const (
	authenticationTokenMaxAgeSeconds = 30 * 86400
)

// Auth allows us to check a username and password, or generate a password for a user.
type Auth interface {
	// Check returns nil if this user/pass combination is legitimate.
	// Otherwise, it returns an error describing the reason it's invalid.
	Check(user, pass string) error
	// PassFor returns a valid password for a given user at the current time.
	PassFor(user string) string
}

// New returns a new production Auth based on the given secret and expiration.
func New(secret []byte) Auth {
	return &auth{secret: secret, clock: util.RealClock, expiration: time.Second * authenticationTokenMaxAgeSeconds}
}

type alwaysAllow struct{}

func (a alwaysAllow) Check(user, pass string) error {
	return nil
}
func (a alwaysAllow) PassFor(user string) string {
	return "wheee"
}

// AlwaysAllow provides an Auth that will always allow clients to connect.
var AlwaysAllow = Auth(alwaysAllow{})

type auth struct {
	secret     []byte
	clock      util.Clock
	expiration time.Duration
}

func (a *auth) Check(user, pass string) error {
	ts, sig, err := a.parsePass(pass)
	if err != nil {
		return err
	}
	return a.valid(user, ts, sig)
}

func (a *auth) parsePass(pass string) (ts time.Time, sig []byte, _ error) {
	i := strings.Index(pass, ":")
	if i < 0 {
		return time.Time{}, nil, fmt.Errorf("no separator")
	}
	unixSecs, err := strconv.ParseInt(pass[:i], 10, 64)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("parsing timestamp: %v", err)
	}
	ts = time.Unix(unixSecs, 0)
	sig, err = hex.DecodeString(pass[i+1:])
	return ts, sig, err
}

func (a *auth) valid(user string, ts time.Time, sig []byte) error {
	diff := a.clock.Now().Sub(ts)
	if diff > a.expiration || diff < -a.expiration {
		return fmt.Errorf("expired")
	}
	mac := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(mac, "%s:%d", user, ts.Unix())
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	if subtle.ConstantTimeCompare(sum[:10], sig) != 1 {
		return fmt.Errorf("mac failure")
	}
	return nil
}

func (a *auth) PassFor(user string) string {
	ts := a.clock.Now()
	mac := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(mac, "%s:%d", user, ts.Unix())
	key := mac.Sum(nil)[:10]
	return fmt.Sprintf("%d:%x", ts.Unix(), key)
}
