// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// package handlers provides http handlers for SVR2 endpoints
package handlers

import (
	"fmt"

	pb "github.com/signalapp/svr2/proto"
)

type EnclaveRequester interface {
	// SendTransaction sends a request to the enclave and returns the enclave's response.
	// Implementations must tag the provided request with a requestID.
	SendTransaction(req *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error)
}

// responseErr check a response for an enclave error status
func responseErr(r *pb.HostToEnclaveResponse) error {
	if e, ok := r.Inner.(*pb.HostToEnclaveResponse_Status); ok && e.Status != pb.Error_OK {
		return fmt.Errorf("transaction %d failed with code: %w", r.RequestId, e.Status)
	}
	return nil
}
