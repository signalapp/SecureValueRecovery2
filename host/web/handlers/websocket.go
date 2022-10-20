// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/armon/go-metrics"
	"github.com/gorilla/websocket"
	"github.com/signalapp/svr2/config"
	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/util"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

// NewWebsocket returns a handler that takes http GET requests and allows clients to
// upgrade to a websocket. They can then use the SVR2 protocol to perform a handshake
// and exchange encrypted messages with the enclave
func NewWebsocket(requestConfig *config.RequestConfig, enclaveRequester EnclaveRequester) http.Handler {
	return &websocketHandler{
		clock:         util.RealClock,
		requestConfig: requestConfig,
		upgrader: websocket.Upgrader{
			HandshakeTimeout:  requestConfig.WebsocketHandshakeTimeout,
			EnableCompression: false,
		},
		enclaveRequester: enclaveRequester,
	}
}

const (
	maxReadLimit = 1024 * 128
)

var (
	enclaveErrorCounterName     = []string{"websocket", "enclaveError"}
	websocketClosureCounterName = []string{"websocket", "closeCode"}
)

type websocketHandler struct {
	clock            util.Clock
	requestConfig    *config.RequestConfig
	enclaveRequester EnclaveRequester
	upgrader         websocket.Upgrader
}

// entrypoint for all app client requests
func (h *websocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, _, _ := r.BasicAuth()
	// Get an ereport from the enclave
	authID, err := hex.DecodeString(user)
	if err != nil {
		http.Error(w, "auth ID invalid hex", http.StatusBadRequest)
		return
	} else if len(authID) != 16 {
		http.Error(w, "auth ID not 16 bytes", http.StatusBadRequest)
		return
	}

	c, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warnw("ws upgrade failed", "err", err)
		return
	}
	defer c.Close()

	c.SetReadLimit(maxReadLimit)

	err = h.handleClientWebsocket(c, authID)
	var wsErr *websocket.CloseError
	if errors.As(err, &wsErr) {
		logger.Debugw("client close error", "err", wsErr)
		labels := [1]metrics.Label{metrics.Label{Name: "code", Value: fmt.Sprintf("%d", wsErr.Code)}}
		metrics.IncrCounterWithLabels(websocketClosureCounterName, 1, labels[:])
		return
	}

	// Send a close frame and forget, no need to wait for close response
	if err := h.writeMessage(c, websocket.CloseMessage, closeMessage(r, err)); err != nil {
		logger.Infow("failed to write close message", "err", err)
	}
}

// Custom websocket close codes
//
// Application errors are [4000, 4015]
const (
	WSBadArgs       = 4003
	WSInternalError = 4013
	WSUnavailable   = 4014
)

// closeMessage builds a websocket closeMessage from an error. If the underlying error
// came from the enclave, it will be marshalled to the appropriate application error.
func closeMessage(r *http.Request, err error) []byte {
	if err == nil {
		return websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	}

	var enclaveErr pb.Error
	if !errors.As(err, &enclaveErr) {
		logger.Warnw("error processing client request", "err", err)
		return websocket.FormatCloseMessage(WSInternalError, "")
	}

	// err might have supplemental error information. Only return enclaveErr in the
	// close frame which only contains static enclave error codes
	msg := enclaveErr.String()
	labels := append(util.ParseTags(r.UserAgent()), metrics.Label{Name: "err", Value: msg})
	metrics.IncrCounterWithLabels(enclaveErrorCounterName, 1, labels)

	logger.Infow("error processing client request", "err", msg)

	switch enclaveErr {
	case pb.Error_DB2_ClientDataSize,
		pb.Error_DB2_ClientPinSize,
		pb.Error_DB2_ClientTriesTooHigh,
		pb.Error_DB2_ClientTriesZero:
		// an issue with the client request outside the client error namespace
		return websocket.FormatCloseMessage(WSBadArgs, msg)

	case pb.Error_Client_EncryptSerialize,
		pb.Error_Client_TransactionInvalid,
		pb.Error_Client_CopyDHState,
		pb.Error_Client_AlreadyClosed:
		// not the client's fault but in the "client" error namespace
		return websocket.FormatCloseMessage(WSInternalError, msg)

	case pb.Error_Client_TransactionCancelled,
		pb.Error_Core_LeaderUnknown:
		// Transient non-serious errors that should just be retried. Guaranteed not to have modified any db state
		return websocket.FormatCloseMessage(WSUnavailable, msg)

	default:
		if pb.Error_Client_NS.Number() < enclaveErr.Number() && enclaveErr < pb.Error_Client_NS+100 {
			// unknown error in the client namespace
			return websocket.FormatCloseMessage(WSBadArgs, msg)
		}
		return websocket.FormatCloseMessage(WSInternalError, msg)
	}
}

func (h *websocketHandler) handleClientWebsocket(c *websocket.Conn, authID []byte) error {
	response, err := h.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_NewClient{NewClient: &pb.NewClientRequest{
			ClientAuthenticatedId: authID,
		}},
	})
	if err != nil {
		return err
	}

	handshake, ok := response.Inner.(*pb.HostToEnclaveResponse_NewClientReply)
	if !ok {
		return errors.New("unexpected enclave proto")
	}
	clientID := handshake.NewClientReply.ClientId
	// Defer cleanup of the client within the enclave once we're done with it.
	// We fire-and-forget this, since it should always succeed on the enclave-side.
	defer h.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
		Inner: &pb.HostToEnclaveRequest_CloseClient{CloseClient: &pb.CloseClientRequest{
			ClientId: clientID,
		}},
	})
	bs, err := proto.Marshal(handshake.NewClientReply.HandshakeStart)
	if err != nil {
		return errors.New("failed to marshal handshake")
	}

	// send ereport to client
	if err := h.writeMessage(c, websocket.BinaryMessage, bs); err != nil {
		return fmt.Errorf("wswrite: %v", err)
	}

	// successfully returned an ereport. now just shunt
	// opaque messages bytes between the client and enclave
	for {
		bs, err := h.readMessage(c)
		if err != nil {
			return fmt.Errorf("wsread: %w", err)
		}
		if bs == nil {
			// websocket close?
			return nil
		}
		reply, err := h.enclaveRequester.SendTransaction(&pb.HostToEnclaveRequest{
			Inner: &pb.HostToEnclaveRequest_ExistingClient{ExistingClient: &pb.ExistingClientRequest{
				ClientId: clientID,
				Data:     bs,
			}},
		})
		if err != nil {
			return err
		}
		if err = responseErr(reply); err != nil {
			return err
		}
		payload, ok := reply.Inner.(*pb.HostToEnclaveResponse_ExistingClientReply)
		if !ok {
			return errors.New("unexpected enclave proto")
		}
		if len(payload.ExistingClientReply.Data) > 0 {
			if err := h.writeMessage(c, websocket.BinaryMessage, payload.ExistingClientReply.Data); err != nil {
				return fmt.Errorf("wswrite: %v", err)
			}
		}
		if payload.ExistingClientReply.Fin {
			return nil
		}
	}
}

func (h *websocketHandler) readMessage(c *websocket.Conn) ([]byte, error) {
	c.SetReadDeadline(h.clock.Now().Add(h.requestConfig.SocketTimeout))
	_, bs, err := c.ReadMessage()
	return bs, err
}

func (h *websocketHandler) writeMessage(c *websocket.Conn, messageType int, data []byte) error {
	c.SetWriteDeadline(h.clock.Now().Add(h.requestConfig.SocketTimeout))
	return c.WriteMessage(messageType, data)
}
