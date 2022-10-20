// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"os"
	"os/signal"

	"github.com/armon/go-metrics/datadog"
	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/service"
	"google.golang.org/protobuf/encoding/prototext"

	stdlog "log"

	metrics "github.com/armon/go-metrics"
	pb "github.com/signalapp/svr2/proto"
)

var (
	enclavePath = flag.String("enclave_path", "", "Path to binary holding the enclave")
	econfigPath = flag.String("econfig_path", "", "Path to enclave configuration prototext file")
	hconfigPath = flag.String("hconfig_path", "", "Path to host configuration yaml file")
)

func main() {
	flag.Parse()

	hconfig, err := config.Read(*hconfigPath)
	if err != nil {
		stdlog.Fatalf("could not read configuration: %v", err)
	}
	logger.Init(hconfig)
	defer logger.Sync()

	// configure metrics
	if hconfig.DatadogAgentHost != "" {
		logger.Infof("initializing datadog at %v", hconfig.DatadogAgentHost)
		sink, err := datadog.NewDogStatsdSink(hconfig.DatadogAgentHost, "")
		if err != nil {
			logger.Fatalf("error initializing statsd client: %v", err)
		}
		defer sink.Shutdown()

		// disable hostname tagging, this can be provided by the downstream sink
		cfg := metrics.DefaultConfig("svr2")
		cfg.EnableHostname = false
		cfg.EnableHostnameLabel = false

		_, err = metrics.NewGlobal(cfg, sink)
		if err != nil {
			logger.Fatalf("error initializing metrics : %v", err)
		}
	}
	authSecret, ok := os.LookupEnv("AUTH_SECRET")
	if !ok {
		logger.Fatalf("no auth secret env (AUTH_SECRET)")
	}
	authBytes, err := base64.StdEncoding.DecodeString(authSecret)
	if err != nil {
		logger.Fatalf("auth secret invalid base64: %v", err)
	}
	authenticator := auth.New(authBytes)

	var econfig pb.InitConfig
	if configBytes, err := os.ReadFile(*econfigPath); err != nil {
		logger.Fatalf("error reading config file %q: %v", *econfigPath, err)
	} else if err = prototext.Unmarshal([]byte(os.ExpandEnv(string(configBytes))), &econfig); err != nil {
		logger.Fatalf("error reading config (ASCII proto): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer func() {
		signal.Stop(interrupts)
		cancel()
	}()

	go func() {
		select {
		case <-interrupts:
			logger.Infof("received interrupt, shutting down...")
			cancel()
		case <-ctx.Done():
		}
	}()

	err = service.Start(ctx, &econfig, hconfig, *enclavePath, authenticator)
	logger.Fatalw("Shutting down", "error", err)
}
