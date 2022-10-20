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
	Sc *client.SVR2Client
}

func (tc *TestClient) Send(req *pb.Request) *pb.Response {
	res, err := tc.Sc.Send(req)
	if err != nil {
		tc.t.Fatalf(err.Error())
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
