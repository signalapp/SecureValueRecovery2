// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gtank/ristretto255"
	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/web/client"

	pb "github.com/signalapp/svr2/proto"
)

var (
	loadtestCmd = flag.NewFlagSet("loadtest", flag.ExitOnError)
	testKeyCmd  = flag.NewFlagSet("testkey", flag.ExitOnError)

	user                     = toUser("test123")
	host, enclaveID, authKey string
	useTLS                   bool
)

var subcommands = map[string]*flag.FlagSet{
	loadtestCmd.Name(): loadtestCmd,
	testKeyCmd.Name():  testKeyCmd,
}

func main() {
	for _, fs := range subcommands {
		fs.StringVar(&host, "host", "backend1.svr3.staging.signal.org", "endpoint to connect to")
		fs.StringVar(&enclaveID, "enclaveId", "7d44d147f38d102c2874ffcd92302398ac2b38592633bb20c75dce9c171fe877", "mrenclave to use")
		fs.StringVar(&authKey, "authKey", "", "base64 encoded shared svr auth key")
		fs.Func("user", "basic auth username. If it's not a 32 character hex string it will be hashed", func(s string) error {
			user = toUser(s)
			return nil
		})
		fs.BoolVar(&useTLS, "useTLS", true, "whether to use TLS")
	}

	switch os.Args[1] {
	case loadtestCmd.Name():
		parallel := loadtestCmd.Int("parallel", 1, "amount of parallelization")
		count := loadtestCmd.Int("count", 1, "total count to run")
		loadtestCmd.Parse(os.Args[2:])
		if err := runLoadTest(*parallel, *count); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	case testKeyCmd.Name():
		testKeyCmd.Parse(os.Args[2:])
		if err := runTestKey(); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	}
}

func toUser(usernameRaw string) string {
	bs, err := hex.DecodeString(usernameRaw)
	if err == nil && len(bs) == 16 {
		return usernameRaw
	}
	h := sha256.Sum256([]byte(usernameRaw))
	return hex.EncodeToString(h[:16])
}

func newClient(username string) (*client.SVRClient, error) {
	u := url.URL{Scheme: "wss", Host: host, Path: fmt.Sprintf("v1/%s", enclaveID)}
	if !useTLS {
		u.Scheme = "ws"
	}
	log.Printf("%v as %v", u, username)
	dialer := *websocket.DefaultDialer
	if useTLS {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	authBytes, err := base64.StdEncoding.DecodeString(authKey)
	if err != nil {
		return nil, err
	}
	c, resp, err := dialer.Dial(u.String(), http.Header{
		"Authorization": []string{"Basic " + base64.URLEncoding.EncodeToString([]byte(username+":"+auth.New(authBytes).PassFor(username)))},
	})
	if err != nil {
		return nil, fmt.Errorf("dial %v", err)
	} else if resp.StatusCode > 299 {
		return nil, fmt.Errorf("code %v", resp.Status)
	}

	return client.NewClient(c)
}

func runLoadTest(parallel, count int) error {
	countU32 := int32(count)
	var wg sync.WaitGroup
	var randBytes [64]byte
	if _, err := io.ReadFull(rand.Reader, randBytes[:]); err != nil {
		return fmt.Errorf("reading random bytes: %w", err)
	}
	e := ristretto255.NewElement().FromUniformBytes(randBytes[:])
	eBytes := e.Encode(nil)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				u := atomic.AddInt32(&countU32, -1)
				if u < 0 {
					return
				} else if u%1000 == 0 {
					log.Printf("running %d/%d", count-int(u), count)
				}
				user := toUser(fmt.Sprintf("%s_%d", user, u))
				// Use the same precomputed element everywhere to avoid CPU load on balancer side.
				if err := runCreate(user, eBytes); err != nil {
					log.Printf("user %d failed create: %v", u, err)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func runTestKey() error {
	var randBytes [64]byte
	if _, err := io.ReadFull(rand.Reader, randBytes[:]); err != nil {
		return fmt.Errorf("reading random bytes: %w", err)
	}
	e := ristretto255.NewElement().FromUniformBytes(randBytes[:])
	eBytes := e.Encode(nil)
	fmt.Printf("Test key: %x\n", eBytes)
	return nil
}

func bytesForUser(username string) []byte {
	h := sha256.Sum256([]byte(username))
	return h[:]
}

func runCreate(username string, blinded []byte) error {
	start := time.Now()
	c, err := newClient(username)
	if err != nil {
		return err
	}

	b := bytesForUser(username)
	r, err := c.Send3(&pb.Request3{Inner: &pb.Request3_Create{
		Create: &pb.CreateRequest{
			MaxTries:       5,
			BlindedElement: blinded,
		},
	}})
	if err != nil {
		return err
	}
	br, ok := r.Inner.(*pb.Response3_Create)
	if !ok {
		return fmt.Errorf("unexpected response : %v", r)
	}
	if br.Create.Status != pb.CreateResponse_OK {
		return fmt.Errorf("backup request not successful: %v", br.Create.Status)
	}
	log.Printf("successful in %v: data=pin=%x", time.Since(start), b)
	return nil
}
