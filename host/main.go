// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	stdlog "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	metrics "github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-metrics/datadog"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/enclave"
	"github.com/signalapp/svr2/logger"
	svr2metrics "github.com/signalapp/svr2/metrics"
	"github.com/signalapp/svr2/service"

	pb "github.com/signalapp/svr2/proto"
)

var (
	sgxPath     = flag.String("sgx_path", "", "Path to binary holding the sgx enclave")
	econfigPath = flag.String("econfig_path", "", "Path to enclave configuration prototext file")
	hconfigPath = flag.String("hconfig_path", "", "Path to host configuration yaml file")
	enclaveType = flag.String("enclave_type", "sgx", "one of {sgx, nitro, sev}")
	nitroPort   = flag.Int("nitro_port", 27427, "Nitro port if --enclave_type=nitro")
	nitroPath   = flag.String("nitro_path", "", "Path to nitro binary for if enclave is simulated")
	nitroCID    = flag.Int("nitro_cid", 16, "Nitro CID")
	sevPort     = flag.Int("sev_port", 27427, "SEV port to use if --enclave_type=sev")
	sevHost     = flag.String("sev_host", "127.0.0.1", "SEV host address to use if --enclave_type=sev")
)

func runSimulatedNitro(ctx context.Context) {
	cmd := exec.CommandContext(ctx, *nitroPath, "--sock_type=af_inet", fmt.Sprintf("--port=%d", *nitroPort))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Fatalf("getting stdout of simulated nitro: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		logger.Fatalf("getting stderr of simulated nitro: %v", err)
	}
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)
	cmd.Start()
	go func() {
		logger.Fatalf("Nitro simulated command finished: %v", cmd.Wait())
	}()
	for start := time.Now(); time.Now().Before(start.Add(time.Second * 30)); time.Sleep(time.Second / 10) {
		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", *nitroPort))
		if err != nil {
			log.Printf("Waiting for nitro port %d: %v", *nitroPort, err)
		} else {
			log.Printf("Successfully connected to nitro port %d", *nitroPort)
			conn.Close()
			return
		}
	}
	log.Fatalf("Unable to connect to nitro port after 30 seconds")
}

func main() {
	flag.Parse()

	hconfig, err := config.Read(*hconfigPath)
	if err != nil {
		stdlog.Fatalf("could not read configuration: %v", err)
	}
	logger.Init(hconfig)
	defer logger.Sync()
	logger.Infof("Host config: %+v", *hconfig)

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

	// configure metrics
	fanoutSink := metrics.FanoutSink{}
	defer fanoutSink.Shutdown()

	// disable hostname tagging, this can be provided by the downstream sink
	cfg := metrics.DefaultConfig("svr2")
	cfg.EnableHostname = false
	cfg.EnableHostnameLabel = false

	if hconfig.DatadogAgentHost != "" {
		logger.Infof("initializing datadog at %v", hconfig.DatadogAgentHost)
		statsdSink, err := datadog.NewDogStatsdSink(hconfig.DatadogAgentHost, "")
		if err != nil {
			logger.Fatalf("error initializing statsd client: %v", err)
		}

		fanoutSink = append(fanoutSink, statsdSink)
	}

	if hconfig.OtlpEnabled {
		logger.Infof("initializing otlp")
		otlpSink, err := svr2metrics.NewOTLPSink(ctx)
		if err != nil {
			logger.Fatalf("error initializing otlp client: %v", err)
		}

		fanoutSink = append(fanoutSink, otlpSink)
	}

	_, err = metrics.NewGlobal(cfg, fanoutSink)
	if err != nil {
		logger.Fatalf("error initializing metrics : %v", err)
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

	var enc enclave.Enclave
	logger.Infof("creating enclave")
	switch *enclaveType {
	case "sgx":
		sgx := enclave.SGXEnclave()
		if err := sgx.Init(*sgxPath, &econfig); err != nil {
			logger.Fatalf("creating sgx enclave: %v", err)
		}
		defer sgx.Close()
		enc = sgx
	case "nitro":
		sc := enclave.SocketConfig{Port: uint32(*nitroPort)}
		if econfig.GroupConfig.Simulated {
			runSimulatedNitro(ctx)
			sc.Host = "127.0.0.1"
		} else {
			sc.VsockCID = uint32(*nitroCID)
		}
		nitro, err := enclave.NewSocket(&econfig, sc)
		if err != nil {
			logger.Fatalf("creating nitro connection: %v", err)
		}
		defer nitro.Close()
		enc = nitro
	case "sev":
		sc := enclave.SocketConfig{Port: uint32(*sevPort), Host: *sevHost}
		sev, err := enclave.NewSocket(&econfig, sc)
		if err != nil {
			logger.Fatalf("creating nitro connection: %v", err)
		}
		defer sev.Close()
		enc = sev
	default:
		logger.Fatalf("invalid enclave type %q", *enclaveType)
	}

	err = service.Start(ctx, hconfig, authenticator, enc)
	logger.Fatalw("Shutting down", "error", err)
}
