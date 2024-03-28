// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peer/peerdb"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/signalapp/svr2/proto"
)

// NewControl returns a handler that takes HTTP PUT requests with a [pb.HostToEnclaveRequest]
// and forwards them to the enclave, returning the enclave's response
func NewControl(server EnclaveRequester) http.Handler {
	return &controlHandler{enclaveRequester: server}
}

type controlHandler struct {
	enclaveRequester EnclaveRequester
}

func (c *controlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}

	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		http.Error(w, fmt.Sprintf("invalid content type %v: %v", err, mediaType), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req := &pb.HostToEnclaveRequest{}
	if err := protojson.Unmarshal(body, req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request proto : %v", err), http.StatusBadRequest)
		return
	}

	if req.RequestId != 0 {
		logger.Warnf("control set request id %v, it will be ignored", req.RequestId)
		req.RequestId = 0
	}

	resp, err := c.enclaveRequester.SendTransaction(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = responseErr(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	out, err := protojson.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(out); err != nil {
		logger.Warnw("error writing control response", "err", err)
	}
}

func NewPeers(peerDB *peerdb.PeerDB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers, err := peerDB.List(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to list peers: %v", err), http.StatusInternalServerError)
			return
		}
		var resp pb.PeerMap
		for id, entry := range peers {
			id := id // shadow/copy
			resp.Entries = append(resp.Entries, &pb.PeerMap_Entry{Id: id[:], Entry: entry})
		}
		out, err := protojson.Marshal(&resp)
		if err != nil {
			http.Error(w, fmt.Sprintf("marshaling JSON: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(out); err != nil {
			logger.Warnw("error writing control response", "err", err)
		}
	})
}
