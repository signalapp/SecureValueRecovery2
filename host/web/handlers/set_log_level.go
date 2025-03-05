// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap/zapcore"

	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"

	pb "github.com/signalapp/svr2/proto"
)

// NewSetLogLevel returns a handler that takes requests to dynamically configure
// the log level. The desired log level should be provided in a POST request with
// "Content-Type: application/x-www-form-urlencoded" body, ex: level=DEBUG
func NewSetLogLevel(config *config.Config, enclaveRequester EnclaveRequester) http.Handler {
	return &setLogLevelHandler{config, enclaveRequester}
}

type setLogLevelHandler struct {
	config           *config.Config
	enclaveRequester EnclaveRequester
}

func (s *setLogLevelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}

	hostLevel, enclaveLevel, err := parseLogLevel(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// set the level on the host
	s.config.Log.Level.SetLevel(hostLevel)

	// set the level on the enclave
	resp, err := s.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_SetLogLevel{
			SetLogLevel: enclaveLevel,
		},
	})
	if err == nil {
		err = responseErr(resp)
	}
	if err != nil {
		logger.Errorw("failed to set enclave log level", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Infof("successfully set log levels, host=%v enclave=%v", hostLevel, enclaveLevel)
	w.WriteHeader(http.StatusOK)
}

func parseLogLevel(values url.Values) (zapcore.Level, pb.EnclaveLogLevel, error) {
	level := values.Get("level")
	if level == "" {
		return zapcore.InvalidLevel, pb.EnclaveLogLevel_LOG_LEVEL_NONE, errors.New("must provide log level")
	}

	switch strings.TrimSpace(strings.ToUpper(level)) {
	case "FATAL":
		return zapcore.ErrorLevel, pb.EnclaveLogLevel_LOG_LEVEL_FATAL, nil
	case "ERROR":
		return zapcore.ErrorLevel, pb.EnclaveLogLevel_LOG_LEVEL_ERROR, nil
	case "WARNING":
		return zapcore.WarnLevel, pb.EnclaveLogLevel_LOG_LEVEL_WARNING, nil
	case "INFO":
		return zapcore.InfoLevel, pb.EnclaveLogLevel_LOG_LEVEL_INFO, nil
	case "DEBUG":
		return zapcore.DebugLevel, pb.EnclaveLogLevel_LOG_LEVEL_DEBUG, nil
	case "VERBOSE":
		return zapcore.DebugLevel, pb.EnclaveLogLevel_LOG_LEVEL_VERBOSE, nil
	case "MAX":
		return zapcore.DebugLevel, pb.EnclaveLogLevel_LOG_LEVEL_MAX, nil
	}
	return zapcore.InvalidLevel, pb.EnclaveLogLevel_LOG_LEVEL_NONE, fmt.Errorf("invalid log level %s", level)
}
