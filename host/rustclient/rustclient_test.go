// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package rustclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/signalapp/svr2/servicetest"
	"google.golang.org/protobuf/encoding/prototext"

	pb "github.com/signalapp/svr2/proto"
)

var (
	validConfig = pb.InitConfig{
		EnclaveConfig: &pb.EnclaveConfig{
			Raft: &pb.RaftConfig{
				ElectionTicks:                 30,
				HeartbeatTicks:                15,
				ReplicationChunkBytes:         1 << 20,
				ReplicaVotingTimeoutTicks:     120,
				ReplicaMembershipTimeoutTicks: 240,
				LogMaxBytes:                   10 << 20,
			},
			E2ETxnTimeoutTicks: 30,
			ClientPq:           true,
		},
		GroupConfig: &pb.RaftGroupConfig{
			DbVersion:          pb.DatabaseVersion_DATABASE_VERSION_SVR2,
			MinVotingReplicas:  1,
			MaxVotingReplicas:  1,
			AttestationTimeout: 3600,
			Simulated:          true,
		},
	}
	hostPath   = "../main"
	sgxPath    = "../../enclave/build/enclave.test"
	clientPath = "target/debug/rustclient"
	authSecret = "123456"
)

func hostConfig(redisAddr string) string {
	return fmt.Sprintf(`
peerAddr: localhost:9990
clientListenAddr: localhost:9991
controlListenAddr: localhost:9992
raft:
  tickDuration: 250ms
redis:
  addrs: [%s]`, redisAddr)
}

func TestRustClient(t *testing.T) {
	dir, err := os.MkdirTemp("", "rustclient")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Logf("using dir %v", dir)
	defer os.RemoveAll(dir)

	redis, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	hConfig := hostConfig(redis.Addr())

	eConfig, err := prototext.Marshal(&validConfig)
	if err != nil {
		t.Fatalf("proto marshal: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "hconfig"), []byte(hConfig), 0600); err != nil {
		t.Fatalf("write hconfig: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "econfig"), eConfig, 0600); err != nil {
		t.Fatalf("write econfig: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostCmd := exec.CommandContext(
		ctx,
		hostPath,
		"-hconfig_path", filepath.Join(dir, "hconfig"),
		"-econfig_path", filepath.Join(dir, "econfig"),
		"-enclave_type", "sgx",
		"-sgx_path", sgxPath)
	hostCmd.Env = append(hostCmd.Env, "AUTH_SECRET="+base64.StdEncoding.EncodeToString([]byte(authSecret)))
	hostCmd.Stdout = servicetest.NewPrefixWriter("HOST_OUT: ", os.Stderr)
	hostCmd.Stderr = servicetest.NewPrefixWriter("HOST_ERR: ", os.Stderr)

	defer time.Sleep(time.Second) // allow logs to make it out.
	t.Logf("Starting...")
	if err := hostCmd.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}

	t.Logf("Waiting for healthy")
	if err := servicetest.WaitFor200(time.Minute, "http://localhost:9992/health/ready"); err != nil {
		t.Fatalf("wait for 200: %v", err)
	}

	t.Logf("Running test")
	u := url.URL{Scheme: "ws", Host: "localhost:9991", Path: "v1/enclave"}
	clientCmd := exec.CommandContext(
		ctx,
		clientPath,
		u.String())
	clientCmd.Stdout = servicetest.NewPrefixWriter("CLIENT_OUT: ", os.Stderr)
	clientCmd.Stderr = servicetest.NewPrefixWriter("CLIENT_ERR: ", os.Stderr)
	if err := clientCmd.Run(); err != nil {
		t.Fatalf("client error: %v", err)
	}
}
