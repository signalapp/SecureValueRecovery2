// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/signalapp/svr2/config"
	"go.uber.org/zap/zapcore"

	pb "github.com/signalapp/svr2/proto"
)

type niceEnclave struct{}
type errorEnclave struct{}

func (*niceEnclave) SendTransaction(p *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error) {
	return &pb.HostToEnclaveResponse{Inner: &pb.HostToEnclaveResponse_Status{
		Status: pb.Error_OK,
	}}, nil
}
func (*errorEnclave) SendTransaction(p *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error) {
	return nil, errors.New("test")
}

func TestEnclaveError(t *testing.T) {
	cfg := config.Default()
	mux := http.NewServeMux()
	mux.Handle("/control/loglevel", NewSetLogLevel(cfg, &errorEnclave{}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.PostForm(fmt.Sprintf("%v/control/loglevel", ts.URL), url.Values{
		"level": []string{"info"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("POST loglevel(name) = %v, want %v", resp.StatusCode, http.StatusInternalServerError)
	}

}

func TestBadArgs(t *testing.T) {
	cfg := config.Default()
	mux := http.NewServeMux()
	mux.Handle("/control/loglevel", NewSetLogLevel(cfg, &niceEnclave{}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, tt := range []url.Values{
		{},
		{"level": []string{"foo"}},
		{"levelz": []string{"info"}},
	} {
		name := fmt.Sprintf("%v", tt)
		t.Run(name, func(t *testing.T) {
			resp, err := http.PostForm(fmt.Sprintf("%v/control/loglevel", ts.URL), url.Values{})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("POST loglevel(name) = %v, want %v", resp.StatusCode, http.StatusBadRequest)
			}

		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		key             string
		level           string
		valid           bool
		expectedHost    zapcore.Level
		expectedEnclave pb.EnclaveLogLevel
	}{
		{"level", "info", true, zapcore.InfoLevel, pb.EnclaveLogLevel_LOG_LEVEL_INFO},
		{"level", "InFo", true, zapcore.InfoLevel, pb.EnclaveLogLevel_LOG_LEVEL_INFO},
		{"level", "verbose", true, zapcore.DebugLevel, pb.EnclaveLogLevel_LOG_LEVEL_VERBOSE},
		{"levelz", "info", false, zapcore.InvalidLevel, pb.EnclaveLogLevel_LOG_LEVEL_NONE},
		{"LEVEL", "info", false, zapcore.InvalidLevel, pb.EnclaveLogLevel_LOG_LEVEL_NONE},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%s=%s", tt.key, tt.level)
		t.Run(name, func(t *testing.T) {
			val := url.Values{}
			val.Set(tt.key, tt.level)
			host, enclave, err := parseLogLevel(val)
			if tt.valid && err != nil {
				t.Errorf("expected success, got %v", err)
			}
			if host != tt.expectedHost {
				t.Errorf("parseLogLevel(%s)=%v, want %v", name, host, tt.expectedHost)
			}
			if enclave != tt.expectedEnclave {
				t.Errorf("parseLogLevel(%s)=%v, want %v", name, enclave, tt.expectedEnclave)
			}
		})
	}
}
