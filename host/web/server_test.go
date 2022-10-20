// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/dispatch"
	"github.com/signalapp/svr2/util"
	"github.com/signalapp/svr2/web/handlers"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

type mockPeerSender struct{}

func (*mockPeerSender) Send(*pb.PeerMessage) error { return nil }

type mockEnclave struct {
	ech chan *pb.EnclaveMessage
	uch chan *pb.UntrustedMessage
}

func (m *mockEnclave) SendMessage(p *pb.UntrustedMessage) error {
	m.uch <- p
	return nil
}

func TestServerMockEnclave(t *testing.T) {
	m := mockEnclave{make(chan *pb.EnclaveMessage), make(chan *pb.UntrustedMessage)}
	txGen := &util.TxGenerator{}
	dispatcher := dispatch.New(config.RaftHostConfig{
		RefreshAttestationDuration: time.Minute,
		TickDuration:               time.Minute,
		MetricPollDuration:         time.Minute,
		EnclaveConcurrency:         3,
	}, txGen, &m, m.ech)
	go dispatcher.Run(context.Background(), &mockPeerSender{})

	mux := http.NewServeMux()
	mux.Handle("/v1/enclave", handlers.NewWebsocket(&config.Default().Request, dispatcher))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	u := url.URL{Scheme: "ws", Host: ts.Listener.Addr().String(), Path: "v1/enclave"}
	log.Println(u.String())
	hdrs := http.Header{}
	hdrs.Add("Authorization", fmt.Sprintf("Basic %s", base64.URLEncoding.EncodeToString([]byte("00112233445566778899aabbccddeeff:foo"))))
	c, resp, err := websocket.DefaultDialer.Dial(u.String(), hdrs)
	if err != nil {
		t.Fatalf("dial: %v %v", err, resp.StatusCode)
	}

	req := <-m.uch
	if req1, ok := req.Inner.(*pb.UntrustedMessage_H2ERequest); !ok {
		t.Errorf("not HostToEnclaveRequest: %v", req)
	} else if _, ok := req1.H2ERequest.Inner.(*pb.HostToEnclaveRequest_NewClient); !ok {
		t.Errorf("not NewClient: %v", req)
	}

	// send a handshake response
	m.ech <- &pb.EnclaveMessage{Inner: &pb.EnclaveMessage_H2EResponse{
		H2EResponse: &pb.HostToEnclaveResponse{
			Inner: &pb.HostToEnclaveResponse_NewClientReply{NewClientReply: &pb.NewClientReply{
				ClientId: 123,
				HandshakeStart: &pb.ClientHandshakeStart{
					Evidence:    []byte{1},
					Endorsement: []byte{2},
				},
			}},
			RequestId: req.GetH2ERequest().RequestId,
		},
	}}
	_, msg, _ := c.ReadMessage()
	var start pb.ClientHandshakeStart
	if err := proto.Unmarshal(msg, &start); err != nil {
		t.Error("unmarshal: ", err)
	}
}
