// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/servicetest"
	"golang.org/x/sync/errgroup"

	pb "github.com/signalapp/svr2/proto"
)

// These tests spin up a full SVR cluster across multiple processes. They require
// a compiled host binary to function, which can be explicitly provided via CLI flag

var (
	sgxPath     = flag.String("sgx_path", "../../enclave/build/enclave.test", "Path to binary holding the enclave")
	nitroPath   = flag.String("nitro_path", "../../enclave/build/enclave.nsm", "Path to nitro binary")
	hostPath    = flag.String("host_path", "../main", "Path to go host binary")
	econfigPath = flag.String("econfig_path", "testdata/enclave.config", "Path to enclave configuration")
	numNodes    = flag.Int("num_nodes", 3, "Number of nodes in the raft group")

	svrGroup   group
	authSecret = "123456"
	data       = []byte("some test data. must be at least 16 bytes")
)

const (
	enclaveSGX   = "sgx"
	enclaveNitro = "nitro"
)

type prefixWriter struct {
	written bool
	prefix  []byte
	to      io.Writer
}

func (p *prefixWriter) Write(bs []byte) (int, error) {
	lastStart := 0
	for i, b := range bs {
		if !p.written {
			if n, err := p.to.Write(bs[lastStart:i]); err != nil {
				return lastStart + n, err
			}
			lastStart = i
			if _, err := p.to.Write(p.prefix); err != nil {
				return i, err
			}
			p.written = true
		} else if b == '\n' {
			p.written = false
		}
	}
	if n, err := p.to.Write(bs[lastStart:]); err != nil {
		return lastStart + n, err
	}
	return len(bs), nil
}
func newPrefixWriter(s string, to io.Writer) io.Writer {
	return &prefixWriter{to: to, prefix: []byte(s)}
}

func userName(i int) string {
	return fmt.Sprintf("%032x", i)
}

func TestIntegration(t *testing.T) {
	host := fmt.Sprintf("localhost:%v", port(clientType, 1))
	u := url.URL{Scheme: "ws", Host: host, Path: "v1/enclave"}
	pin := backup(t, testClient(t, u, userName(9999)))
	expose(t, testClient(t, u, userName(9999)))
	restore(t, testClient(t, u, userName(9999)), pin)
}

func TestRustClient(t *testing.T) {
	host := fmt.Sprintf("localhost:%v", port(clientType, 1))
	u := url.URL{Scheme: "ws", Host: host, Path: "v1/enclave"}
	cmd := exec.Command("./rustclient/target/debug/rustclient", u.String())
	w := newPrefixWriter("RUSTCLIENT ", os.Stderr)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		t.Errorf("rustclient: %v", err)
	}
}

func TestConcurrentClients(t *testing.T) {
	host := fmt.Sprintf("localhost:%v", port(clientType, 1))
	u := url.URL{Scheme: "ws", Host: host, Path: "v1/enclave"}

	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		user := userName(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			pin := backup(t, testClient(t, u, user))
			expose(t, testClient(t, u, user))
			restore(t, testClient(t, u, user), pin)
		}()
	}
	wg.Wait()
}

func TestServerDelete(t *testing.T) {
	user := userName(123)
	host := fmt.Sprintf("localhost:%v", port(clientType, 1))
	u := url.URL{Scheme: "ws", Host: host, Path: "v1/enclave"}
	pin := backup(t, testClient(t, u, user))
	expose(t, testClient(t, u, user))
	restore(t, testClient(t, u, user), pin)

	// use the server http endpoint to delete the backup for user
	deleteURL := fmt.Sprintf("http://localhost:%v/v1/delete", port(clientType, 2))
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = authHeaders(user)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete failed: %v", string(body))
	}

	// use the websocket to check that it's really gone
	tc := testClient(t, u, user)
	r := tc.Send(&pb.Request{Inner: &pb.Request_Restore{
		Restore: &pb.RestoreRequest{
			Pin: pin,
		},
	}})
	if rr, ok := r.Inner.(*pb.Response_Restore); !ok {
		t.Fatalf("Unexpected response to restore: %v", r)
	} else if rr.Restore.Status != pb.RestoreResponse_MISSING {
		t.Fatalf("Incorrect response: %v, backup should be missing", rr)
	}
}

func authHeaders(user string) http.Header {
	authenticator := auth.New([]byte(authSecret))
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.URLEncoding.EncodeToString([]byte(user+":"+authenticator.PassFor(user))))
	return headers
}

func testClient(t *testing.T, u url.URL, user string) *servicetest.TestClient {
	headers := authHeaders(user)
	log.Printf("using headers: %+v", headers)
	c, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	return servicetest.NewTestClient(t, c)
}

func backup(t *testing.T, tc *servicetest.TestClient) (pin []byte) {
	// send a backup request
	defer tc.Sc.Close()
	pin = servicetest.RandBytes(t, 32)

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
	return
}

func expose(t *testing.T, tc *servicetest.TestClient) {
	defer tc.Sc.Close()
	// send a expose request
	r := tc.Send(&pb.Request{Inner: &pb.Request_Expose{
		Expose: &pb.ExposeRequest{
			Data: data,
		},
	}})
	if br, ok := r.Inner.(*pb.Response_Expose); !ok {
		t.Fatalf("Unexpected response to expose: %v", r)
	} else if br.Expose.Status != pb.ExposeResponse_OK {
		t.Fatalf("Incorrect response: %v", br)
	}
}

func restore(t *testing.T, tc *servicetest.TestClient, pin []byte) {
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
	} else if !bytes.Equal(rr.Restore.Data, data) {
		t.Fatalf("Restored bytes %v, want %v", rr.Restore.Data, data)
	}
}

func run(m *testing.M, enclaveType string) int {
	group := start(enclaveType)
	defer group.stop()
	return m.Run()
}

func initializeAndRun(m *testing.M) int {
	return run(m, enclaveSGX) + run(m, enclaveNitro)
}

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		return
	}
	os.Exit(initializeAndRun(m))
}

type group struct {
	cancel context.CancelFunc
	ctx    context.Context
	dir    string
	eg     *errgroup.Group
}

type addrType int

const (
	controlType addrType = iota
	clientType
	peerType
	nitroType
)

func port(typ addrType, portOffset int) int {
	switch typ {
	case controlType:
		return 8090 + portOffset
	case clientType:
		return 8080 + portOffset
	case peerType:
		return 9000 + portOffset
	case nitroType:
		return 10000 + portOffset
	}
	return 0
}

func hconfig(w io.Writer, dir string, portOffset int, redisAddr string) error {
	_, err := fmt.Fprintf(w, `
peerAddr: localhost:%v
clientListenAddr: localhost:%v
controlListenAddr: localhost:%v
raft:
  tickDuration: 250ms
redis:
  addrs: [%v]`,
		port(peerType, portOffset),
		port(clientType, portOffset),
		port(controlType, portOffset),
		redisAddr)
	return err
}

func (g *group) stop() {
	g.cancel()
	g.eg.Wait()
	os.RemoveAll(g.dir)
}

func start(enclaveType string) group {
	ctx, cancel := context.WithCancel(context.Background())
	eg, ctx := errgroup.WithContext(ctx)

	dir, err := os.MkdirTemp("", "host")
	if err != nil {
		log.Fatal(err)
	}

	redis, err := miniredis.Run()
	if err != nil {
		log.Fatal(err)
	}
	defer redis.Close()

	// start numNodes SVR processes
	for i := 1; i <= *numNodes; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("hostconfig-%d", i)))
		if err != nil {
			log.Fatalf("create tempfile : %v", err)
		}
		if err := hconfig(f, dir, i, redis.Addr()); err != nil {
			log.Fatalf("write config : %v", err)
		}
		f.Close()

		args := []string{
			"-hconfig_path", f.Name(),
			"-econfig_path", *econfigPath,
		}
		switch enclaveType {
		case enclaveSGX:
			args = append(args,
				"-enclave_type", enclaveSGX,
				"-sgx_path", *sgxPath)
		case enclaveNitro:
			args = append(args,
				"-enclave_type", enclaveNitro,
				"-nitro_path", *nitroPath,
				"-nitro_port", fmt.Sprintf("%d", port(nitroType, i)))
		}
		cmd := exec.CommandContext(
			ctx,
			*hostPath,
			args...)
		cmd.Env = append(cmd.Env, "AUTH_SECRET="+base64.StdEncoding.EncodeToString([]byte(authSecret)))

		w := newPrefixWriter(fmt.Sprintf("[%d] ", i), os.Stderr)
		cmd.Stdout = w
		cmd.Stderr = w

		if err = cmd.Start(); err != nil {
			log.Fatalf("cmd start: %v", err)
		}

		eg.Go(func() error {
			return cmd.Wait()
		})

		url := fmt.Sprintf("http://localhost:%v/health/ready", port(controlType, i))
		if err := servicetest.WaitFor200(time.Minute, url); err != nil {
			log.Printf("ERROR: %v", err)
			cancel()
			eg.Wait()
			log.Fatal(err)
		}
	}

	return group{
		cancel: cancel,
		ctx:    ctx,
		dir:    dir,
		eg:     eg,
	}

}
