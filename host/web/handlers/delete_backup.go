// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"encoding/hex"
	"net/http"

	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

// NewDeleteBackup returns a handler that takes HTTP DELETE requests and notifies
// the enclave to delete the backup associated with the user (provided via basic auth)
func NewDeleteBackup(server EnclaveRequester) http.Handler {
	return &deleteBackupHandler{
		enclaveRequester: server,
	}
}

type deleteBackupHandler struct {
	enclaveRequester EnclaveRequester
}

func (d *deleteBackupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "only DELETE allowed", http.StatusMethodNotAllowed)
		return
	}
	user, _, _ := r.BasicAuth()
	authID, err := hex.DecodeString(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if len(authID) != 16 {
		http.Error(w, "auth ID not 16 bytes", http.StatusBadRequest)
		return
	}
	deleteReq := pb.Request{
		Inner: &pb.Request_Delete{Delete: &pb.DeleteRequest{}},
	}
	marshalled, err := proto.Marshal(&deleteReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := d.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_DatabaseRequest{
			DatabaseRequest: &pb.DatabaseRequest{
				Request:         marshalled,
				AuthenticatedId: authID,
			},
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = responseErr(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
