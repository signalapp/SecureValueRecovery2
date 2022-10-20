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
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/signalapp/svr2/auth"
	"github.com/signalapp/svr2/web/client"

	pb "github.com/signalapp/svr2/proto"
)

var (
	backupCmd   = flag.NewFlagSet("backup", flag.ExitOnError)
	exposeCmd   = flag.NewFlagSet("expose", flag.ExitOnError)
	restoreCmd  = flag.NewFlagSet("restore", flag.ExitOnError)
	deleteCmd   = flag.NewFlagSet("delete", flag.ExitOnError)
	loadtestCmd = flag.NewFlagSet("loadtest", flag.ExitOnError)

	user                     = toUser("test123")
	host, enclaveID, authKey string
	useTLS                   bool
)

var subcommands = map[string]*flag.FlagSet{
	backupCmd.Name():   backupCmd,
	exposeCmd.Name():   exposeCmd,
	restoreCmd.Name():  restoreCmd,
	deleteCmd.Name():   deleteCmd,
	loadtestCmd.Name(): loadtestCmd,
}

func main() {
	for _, fs := range subcommands {
		fs.StringVar(&host, "host", "svr2.staging.signal.org", "endpoint to connect to")
		fs.StringVar(&enclaveID, "enclaveId", "7d44d147f38d102c2874ffcd92302398ac2b38592633bb20c75dce9c171fe877", "mrenclave to use")
		fs.StringVar(&authKey, "authKey", "", "base64 encoded shared svr auth key")
		fs.Func("user", "basic auth username. If it's not a 32 character hex string it will be hashed", func(s string) error {
			user = toUser(s)
			return nil
		})
		fs.BoolVar(&useTLS, "useTLS", true, "whether to use TLS")
	}

	switch os.Args[1] {
	case backupCmd.Name():
		backupCmd.Parse(os.Args[2:])
		if err := runBackup(user); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	case exposeCmd.Name():
		exposeCmd.Parse(os.Args[2:])
		if err := runExpose(user); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	case restoreCmd.Name():
		var pin string
		restoreCmd.StringVar(&pin, "pin", "", "pin")
		restoreCmd.Parse(os.Args[2:])
		if err := runRestore(pin); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	case deleteCmd.Name():
		deleteCmd.Parse(os.Args[2:])
		if err := runDelete(); err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	case loadtestCmd.Name():
		parallel := loadtestCmd.Int("parallel", 1, "amount of parallelization")
		count := loadtestCmd.Int("count", 1, "total count to run")
		loadtestCmd.Parse(os.Args[2:])
		if err := runLoadTest(*parallel, *count); err != nil {
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

func newClient(username string) (*client.SVR2Client, error) {
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

func runRestore(hexPin string) error {
	c, err := newClient(user)
	if err != nil {
		return err
	}
	pin, err := hex.DecodeString(hexPin)
	if err != nil {
		return err
	}

	r, err := c.Send(&pb.Request{Inner: &pb.Request_Restore{
		Restore: &pb.RestoreRequest{
			Pin: pin,
		},
	}})
	if err != nil {
		return err
	}
	log.Print(r)
	return nil

}

func runLoadTest(parallel, count int) error {
	countU32 := int32(count)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				u := atomic.AddInt32(&countU32, -1)
				if u < 0 {
					return
				}
				user := toUser(fmt.Sprintf("%s_%d", user, u))
				if err := runBackup(user); err != nil {
					log.Printf("user %d failed backup: %v", u, err)
				}
				if err := runExpose(user); err != nil {
					log.Printf("user %d failed expose: %v", u, err)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func bytesForUser(username string) []byte {
	h := sha256.Sum256([]byte(username))
	return h[:]
}

func runBackup(username string) error {
	c, err := newClient(username)
	if err != nil {
		return err
	}

	b := bytesForUser(username)
	r, err := c.Send(&pb.Request{Inner: &pb.Request_Backup{
		Backup: &pb.BackupRequest{
			Data:     b,
			Pin:      b,
			MaxTries: 5,
		},
	}})
	if err != nil {
		return err
	}
	br, ok := r.Inner.(*pb.Response_Backup)
	if !ok {
		return fmt.Errorf("unexpected response : %v", r)
	}
	if br.Backup.Status != pb.BackupResponse_OK {
		return fmt.Errorf("backup request not successful: %v", br.Backup.Status)
	}
	log.Printf("successful: data=pin=%x", b)
	return nil
}

func runExpose(username string) error {
	c, err := newClient(username)
	if err != nil {
		return err
	}

	b := bytesForUser(username)
	r, err := c.Send(&pb.Request{Inner: &pb.Request_Expose{
		Expose: &pb.ExposeRequest{
			Data: b,
		},
	}})
	if err != nil {
		return err
	}
	br, ok := r.Inner.(*pb.Response_Expose)
	if !ok {
		return fmt.Errorf("unexpected response : %v", r)
	}
	if br.Expose.Status != pb.ExposeResponse_OK {
		return fmt.Errorf("backup request not successful: %v", br.Expose.Status)
	}
	log.Printf("successful")
	return nil
}

func runDelete() error {
	c, err := newClient(user)
	if err != nil {
		return err
	}

	r, err := c.Send(&pb.Request{Inner: &pb.Request_Delete{Delete: &pb.DeleteRequest{}}})
	if err != nil {
		return err
	}
	log.Print(r)
	return nil
}

func randBytes(count int) []byte {
	bs := make([]byte, count)
	if _, err := rand.Read(bs); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return bs
}
