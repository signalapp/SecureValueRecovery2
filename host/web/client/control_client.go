// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/signalapp/svr2/proto"
)

type ControlClient struct {
	Addr string
}

func (cc *ControlClient) Do(request *pb.HostToEnclaveRequest) (*pb.HostToEnclaveResponse, error) {
	bs, err := protojson.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto : %w", err)
	}
	return cc.DoJSON(bs)
}

func (cc *ControlClient) DoJSON(request []byte) (*pb.HostToEnclaveResponse, error) {
	url := fmt.Sprintf("http://%v/control", cc.Addr)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(request))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed : %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed, status=%v, body=%s", resp.Status, body)
	}

	pbResponse := pb.HostToEnclaveResponse{}
	if err := protojson.Unmarshal(body, &pbResponse); err != nil {
		return nil, fmt.Errorf("could not parse server response, body=%s : %w", body, err)
	}
	return &pbResponse, nil
}
