// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package health

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServingFromHealthy(t *testing.T) {
	h := New(nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("nil error returned status: %v", res.Status)
	}
	h.Set(errors.New("FUBAR"))
	res, err = http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("non-nil error returned status: %v", res.Status)
	}
}

func TestServingFromUnhealthy(t *testing.T) {
	h := New(errors.New("FUBAR"))
	ts := httptest.NewServer(h)
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("non-nil error returned status: %v", res.Status)
	}
	h.Set(nil)
	res, err = http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("nil error returned status: %v", res.Status)
	}
}
