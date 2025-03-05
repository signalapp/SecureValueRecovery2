// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"

	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/enclave"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/servicetest"
	"github.com/signalapp/svr2/web/client"

	pb "github.com/signalapp/svr2/proto"
)

func waitForReady(t *testing.T, controlAddr string, timeout time.Duration) {
	url := fmt.Sprintf("http://%v/health/ready", controlAddr)
	if err := servicetest.WaitFor200(timeout, url); err != nil {
		t.Fatal(err)
	}
}

func randomPort(t *testing.T) int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port

}

func dial(t *testing.T, cfg *config.Config) *websocket.Conn {
	u := url.URL{Scheme: "ws", Host: cfg.ClientListenAddr, Path: "v1/enclave"}
	hdrs := http.Header{}
	hdrs.Add("Authorization", fmt.Sprintf("Basic %s", base64.URLEncoding.EncodeToString([]byte("00112233445566778899aabbccddeeff:foo"))))
	c, _, err := websocket.DefaultDialer.Dial(u.String(), hdrs)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func backup(t *testing.T, tc *servicetest.TestClient, pin []byte, data []byte) {
	// send a backup request
	defer tc.Sc.Close()
	r := tc.Send(&pb.Request{Inner: &pb.Request_Backup{
		Backup: &pb.BackupRequest{
			Data:     data,
			Pin:      pin,
			MaxTries: 5,
		},
	}})
	if br, ok := r.Inner.(*pb.Response_Backup); !ok {
		t.Fatalf("Unexpected response to backup: %v", r)
	} else if br.Backup.Status != pb.BackupResponse_OK {
		t.Fatalf("Incorrect response: %v", br)
	}
}

func expose(t *testing.T, tc *servicetest.TestClient, data []byte) {
	defer tc.Sc.Close()
	// send a expose request
	r := tc.Send(&pb.Request{Inner: &pb.Request_Expose{
		Expose: &pb.ExposeRequest{
			Data: data,
		},
	}})
	if br, ok := r.Inner.(*pb.Response_Expose); !ok {
		t.Fatalf("Unexpected response to backup: %v", r)
	} else if br.Expose.Status != pb.ExposeResponse_OK {
		t.Fatalf("Incorrect response: %v", br)
	}
}

func restore(t *testing.T, tc *servicetest.TestClient, pin []byte, expectedData []byte) {
	defer tc.Sc.Close()
	// send a restore request
	r := tc.Send(&pb.Request{Inner: &pb.Request_Restore{
		Restore: &pb.RestoreRequest{
			Pin: pin,
		},
	}})
	if rr, ok := r.Inner.(*pb.Response_Restore); !ok {
		t.Fatalf("Unexpected response to restore: %v", r)
	} else if rr.Restore.Status != pb.RestoreResponse_OK {
		t.Fatalf("Incorrect response: %v", rr)
	} else if !bytes.Equal(rr.Restore.Data, expectedData) {
		t.Fatalf("Restored bytes %v, want %v", rr.Restore.Data, expectedData)
	}
}

func startService(t *testing.T) *config.Config {
	redis := miniredis.RunT(t)

	hconfig := config.Default()
	hconfig.ClientListenAddr = fmt.Sprintf("localhost:%v", randomPort(t))
	hconfig.ControlListenAddr = fmt.Sprintf("localhost:%v", randomPort(t))
	hconfig.PeerAddr = fmt.Sprintf("localhost:%v", randomPort(t))
	hconfig.Redis.Addrs = []string{redis.Addr()}

	econfig := pb.InitConfig{
		EnclaveConfig: &pb.EnclaveConfig{
			E2ETxnTimeoutTicks: 30,
			Raft: &pb.RaftConfig{
				ElectionTicks:                 30,
				HeartbeatTicks:                15,
				ReplicationChunkBytes:         1048576,
				ReplicaVotingTimeoutTicks:     60,
				ReplicaMembershipTimeoutTicks: 300,
				LogMaxBytes:                   10 << 20,
			},
		},
		GroupConfig: &pb.RaftGroupConfig{
			DbVersion:          pb.DatabaseVersion_DATABASE_VERSION_SVR2,
			MinVotingReplicas:  1,
			MaxVotingReplicas:  5,
			AttestationTimeout: 3600,
			Simulated:          true,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		logger.Errorf("Finishing (canceling) test")
		cancel()
	})

	sgx := enclave.SGXEnclave()
	if err := sgx.Init("../../enclave/build/enclave.test", &econfig); err != nil {
		logger.Fatalf("creating sgx enclave: %v", err)
	}
	logger.Infof("Starting SGX service")
	go func() {
		defer sgx.Close()
		Start(ctx, hconfig, auth.AlwaysAllow, sgx)
	}()
	waitForReady(t, hconfig.ControlListenAddr, time.Minute)
	return hconfig
}

func TestService(t *testing.T) {
	// The enclave can only be initialized once, so only run setup once
	cfg := startService(t)
	t.Run("TestSetLogLevel", func(t *testing.T) {
		testSetLogLevel(t, cfg)
	})
	t.Run("TestBackupRestore", func(t *testing.T) {
		testBackupRestore(t, cfg)
	})
	t.Run("TestBadArgs", func(t *testing.T) {
		testBadArgs(t, cfg)
	})
	t.Run("TestKeyRotation", func(t *testing.T) {
		testKeyRotation(t, cfg)
	})
}

func testSetLogLevel(t *testing.T, cfg *config.Config) {
	orig := cfg.Log.Level.Level()
	cfg.Log.Level.SetLevel(zapcore.ErrorLevel)
	logger.Init(cfg)

	isEnabled := func(level zapcore.Level) bool {
		return zap.L().Check(level, "test") != nil
	}

	if !isEnabled(zapcore.ErrorLevel) {
		t.Errorf("isEnabled(Error) = false, want true")
	}

	if isEnabled(zapcore.InfoLevel) {
		t.Errorf("isEnabled(Info) = true, want false")
	}

	// use the server http endpoint to delete the backup for user
	controlURL := fmt.Sprintf("http://%v/control/loglevel", cfg.ControlListenAddr)
	resp, err := http.PostForm(controlURL, url.Values{"level": []string{"info"}})
	if err != nil {
		t.Fatal(err)
	}
	defer http.PostForm(controlURL, url.Values{"level": []string{orig.String()}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bs, _ := ioutil.ReadAll(resp.Body)
		t.Errorf("PUT loglevel = %v:%s, want %v", resp.Status, bs, http.StatusOK)
	}

	if !isEnabled(zapcore.InfoLevel) {
		t.Errorf("isEnabled(Info) = false, want true")
	}

}

func testBackupRestore(t *testing.T, cfg *config.Config) {

	// send a backup request
	pin := servicetest.RandBytes(t, 32)
	data := servicetest.RandBytes(t, 40)
	tc := servicetest.NewTestClient(t, dial(t, cfg))
	backup(t, tc, pin, data)

	tc = servicetest.NewTestClient(t, dial(t, cfg))
	expose(t, tc, data)

	// send a restore request
	tc = servicetest.NewTestClient(t, dial(t, cfg))
	restore(t, tc, pin, data)
}

func testBadArgs(t *testing.T, cfg *config.Config) {
	c := dial(t, cfg)

	// read the handshake start message
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Error(err)
	}

	var start pb.ClientHandshakeStart
	if err := proto.Unmarshal(msg, &start); err != nil {
		t.Error(err)
	}

	// send garbage
	if err := c.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Error(err)
	}

	_, _, err = c.ReadMessage()
	var wsErr *websocket.CloseError
	if !errors.As(err, &wsErr) {
		t.Fatalf("expected close frame error, got err = %v", err)
	}
	if wsErr.Code != 4003 {
		t.Fatalf("bad handshake got close code %v, want %v", wsErr.Code, 4003)
	}
}

func testKeyRotation(t *testing.T, cfg *config.Config) {

	// handshake with old public key
	tc := servicetest.NewTestClient(t, dial(t, cfg))

	// force a rekey
	cc := client.ControlClient{Addr: cfg.ControlListenAddr}
	refreshReq := pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_RefreshAttestation{
			RefreshAttestation: &pb.RefreshAttestation{RotateClientKey: true},
		},
	}
	if resp, err := cc.Do(&refreshReq); err != nil {
		t.Fatal(err)
	} else if resp.GetStatus() != pb.Error_OK {
		t.Fatalf("RefreshAttestation(true)=%v, want=%v", resp.GetStatus(), pb.Error_OK)
	}

	// should be able to do a backup even after rekey
	pin := servicetest.RandBytes(t, 32)
	data := servicetest.RandBytes(t, 40)
	backup(t, tc, pin, data)

	oldkey := tc.Sc.PubKey
	tc = servicetest.NewTestClient(t, dial(t, cfg))
	if bytes.Equal(tc.Sc.PubKey, oldkey) {
		t.Fatalf("handshake key should not match after key rotation")
	}
	tc.Send(&pb.Request{Inner: &pb.Request_Delete{Delete: &pb.DeleteRequest{}}})
}
