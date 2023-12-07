// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
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

	user                                    = toUser("test123")
	hosts, enclaveID, authKey, statFilename string
	useTLS                                  bool
)

var subcommands = map[string]*flag.FlagSet{
	loadtestCmd.Name(): loadtestCmd,
	testKeyCmd.Name():  testKeyCmd,
}

func main() {
	for _, fs := range subcommands {
		fs.StringVar(&hosts, "host", "backend1.svr3.staging.signal.org", "endpoint(s) to connect to (comma separated)")
		fs.StringVar(&enclaveID, "enclaveId", "7d44d147f38d102c2874ffcd92302398ac2b38592633bb20c75dce9c171fe877", "mrenclave to use")
		fs.StringVar(&authKey, "authKey", "", "base64 encoded shared svr auth key")
		fs.Func("user", "basic auth username. If it's not a 32 character hex string it will be hashed", func(s string) error {
			user = toUser(s)
			return nil
		})
		fs.BoolVar(&useTLS, "useTLS", true, "whether to use TLS")
		fs.StringVar(&statFilename, "filename", "", "Filename where statistics will be stored")
	}

	switch os.Args[1] {
	case loadtestCmd.Name():
		parallel := loadtestCmd.Int("parallel", 1, "amount of parallelization")
		count := loadtestCmd.Int("count", 1, "total count to run")
		loadtestCmd.Parse(os.Args[2:])
		hs := newHostSet(strings.Split(hosts, ","))
		if err := runLoadTest(*parallel, *count, hs); err != nil {
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

type hostSet struct {
	mu    sync.Mutex
	hosts map[string]uint64
}

func newHostSet(hosts []string) *hostSet {
	hs := &hostSet{hosts: map[string]uint64{}}
	for _, h := range hosts {
		hs.hosts[h] = 0
	}
	return hs
}

func (h *hostSet) getHost() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	min := uint64(math.MaxUint64)
	out := ""
	for host, c := range h.hosts {
		if min > c {
			min = c
			out = host
		}
	}
	min++
	h.hosts[out] = min
	log.Printf("using host %q (now %d outstanding)", out, min)
	return out
}
func (h *hostSet) returnHost(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hosts[host] -= 1
}

func newClient(username string, hs *hostSet) (*client.SVRClient, error) {
	host := hs.getHost()
	defer hs.returnHost(host)
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

func runLoadTest(parallel, count int, hs *hostSet) error {
	count32 := int32(count)
	create_latencies := make([]int64, count)
	restore_latencies := make([]int64, count)
	var create_time, restore_time int64 = 0, 0
	var wg sync.WaitGroup
	var randBytes [64]byte
	if _, err := io.ReadFull(rand.Reader, randBytes[:]); err != nil {
		return fmt.Errorf("reading random bytes: %w", err)
	}
	e := ristretto255.NewElement().FromUniformBytes(randBytes[:])
	eBytes := e.Encode(nil)

	var create_start = time.Now()
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				u := atomic.AddInt32(&count32, -1)
				if u < 0 {
					return
				} else if u%1000 == 0 {
					log.Printf("running create %d/%d", count-int(u), count)
				}
				user := toUser(fmt.Sprintf("%s_%d", user, u))
				// Use the same precomputed element everywhere to avoid CPU load on balancer side.
				var start = time.Now()
				if err := runCreate(user, eBytes, hs); err != nil {
					log.Printf("user %d failed create: %v", u, err)
				}
				latency := time.Since(start).Microseconds()
				create_latencies[u] = latency
			}
		}()
	}
	wg.Wait()
	create_time = time.Since(create_start).Microseconds()

	count32 = int32(count)
	var restore_start = time.Now()
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				u := atomic.AddInt32(&count32, -1)
				if u < 0 {
					return
				} else if u%1000 == 0 {
					log.Printf("running restore %d/%d", count-int(u), count)
				}
				user := toUser(fmt.Sprintf("%s_%d", user, u))
				// Use the same precomputed element everywhere to avoid CPU load on balancer side.
				var start = time.Now()
				if err := runRestore(user, eBytes, hs); err != nil {
					log.Printf("user %d failed restore: %v", u, err)
				}

				latency := time.Since(start).Microseconds()
				restore_latencies[u] = latency
			}
		}()
	}
	wg.Wait()
	restore_time = time.Since(restore_start).Microseconds()
	log.Printf("count: %d", count)
	log.Printf("parallel: %d", parallel)
	log.Printf("create total: %d", create_time)
	log.Printf("restore total: %d", restore_time)
	if statFilename != "" {
		// post process latencies to compute states
		var create_max, create_min, create_sum int64 = 0, math.MaxInt64, 0
		var restore_max, restore_min, restore_sum int64 = 0, math.MaxInt64, 0
		for i := 0; i < count; i++ {
			create_latency := create_latencies[i]
			restore_latency := restore_latencies[i]
			if create_max < create_latency {
				create_max = create_latency
			}
			if create_min > create_latency && create_latency > 0 {
				create_min = create_latency
			}
			create_sum = create_sum + create_latency

			if restore_max < restore_latency {
				restore_max = restore_latency
			}
			if create_min > restore_latency && restore_latency > 0 {
				create_min = restore_latency
			}
			restore_sum = restore_sum + restore_latency
		}
		f, err := os.Create(statFilename)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		w := bufio.NewWriter(f)

		fmt.Fprintf(w, "count,%d\n", count)
		fmt.Fprintf(w, "parallel,%d\n", parallel)
		fmt.Fprintf(w, "create_min,%d\n", create_min)
		fmt.Fprintf(w, "create_max,%d\n", create_max)
		fmt.Fprintf(w, "create_mean,%f\n", float64(create_sum)/float64(count))
		fmt.Fprintf(w, "create throughput,%f\n", 1000000.0*float64(count)/float64(create_time))

		fmt.Fprintf(w, "restore_min,%d\n", restore_min)
		fmt.Fprintf(w, "restore_max,%d\n", restore_max)
		fmt.Fprintf(w, "restore_mean,%f\n", float64(restore_sum)/float64(count))
		fmt.Fprintf(w, "restore throughput,%f\n", 1000000.0*float64(count)/float64(restore_time))

		fmt.Fprintf(w, "create,restore\n")
		for u := 0; u < count; u++ {
			fmt.Fprintf(w, "%d,%d\n", create_latencies[u], restore_latencies[u])
		}

	}

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

func runCreate(username string, blinded []byte, hs *hostSet) error {
	start := time.Now()
	c, err := newClient(username, hs)
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
	log.Printf("create successful in %v: data=pin=%x", time.Since(start), b)
	return nil
}

func runRestore(username string, blinded []byte, hs *hostSet) error {
	start := time.Now()
	c, err := newClient(username, hs)
	if err != nil {
		return err
	}

	b := bytesForUser(username)
	r, err := c.Send3(&pb.Request3{Inner: &pb.Request3_Evaluate{
		Evaluate: &pb.EvaluateRequest{
			BlindedElement: blinded,
		},
	}})
	if err != nil {
		return err
	}
	br, ok := r.Inner.(*pb.Response3_Evaluate)
	if !ok {
		return fmt.Errorf("unexpected response : %v", r)
	}
	if br.Evaluate.Status != pb.EvaluateResponse_OK {
		return fmt.Errorf("evaluate request not successful: %v", br.Evaluate.Status)
	}
	log.Printf("restore successful in %v: data=pin=%x", time.Since(start), b)
	return nil
}
