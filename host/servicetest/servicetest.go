// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package servicetest

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/signalapp/svr2/util"
	"github.com/signalapp/svr2/web/client"

	pb "github.com/signalapp/svr2/proto"
)

type TestClient struct {
	t  *testing.T
	Sc *client.SVRClient
}

func (tc *TestClient) Send(req *pb.Request) *pb.Response {
	res, err := tc.Sc.Send2(req)
	if err != nil {
		tc.t.Fatalf("error sending request: %v", err)
	}
	return res
}

func NewTestClient(t *testing.T, c *websocket.Conn) *TestClient {
	client, err := client.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	return &TestClient{t, client}
}

func RandBytes(t *testing.T, count uint32) []byte {
	bs := make([]byte, count)
	if _, err := rand.Read(bs); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return bs
}

func RetryFun[T any](timeout time.Duration, fun func() (T, error)) (T, error) {
	timech := time.After(timeout)
	var err error
	var res T
	for {
		select {
		case <-timech:
			return res, fmt.Errorf("timeout: %w", err)
		default:
			if res, err = fun(); err == nil {
				return res, nil
			}
			time.Sleep(util.Min(time.Second, timeout/10))
		}
	}
}

func WaitFor200(timeout time.Duration, url string) error {
	_, err := RetryFun(timeout, func() (interface{}, error) {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("status=%v : %v", resp.Status, body)
		}
		return nil, nil
	})
	return err
}

type PrefixWriter struct {
	written bool
	prefix  []byte
	to      io.Writer
}

func (p *PrefixWriter) Write(bs []byte) (int, error) {
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
func NewPrefixWriter(s string, to io.Writer) io.Writer {
	return &PrefixWriter{to: to, prefix: []byte(s)}
}
