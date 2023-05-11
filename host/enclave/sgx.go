// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package enclave connects the Go binary to C code.
//
// This package connects up ocalls/ecalls and associated OpenEnclave APIs and
// exposes them in a Go-y way to the rest of the project.
package enclave

/*
#cgo pkg-config: oehost-g++
#cgo LDFLAGS: -L./c -lsvr2
#include "c/svr2_u.h"
#include <openenclave/trace.h>
#include <signal.h>

// Defined in `callback.go`
void svr2OutputMessageGoCallback(size_t msg_size, unsigned char* msg);

void svr2_output_message(size_t msg_size, unsigned char* msg) {
  svr2OutputMessageGoCallback(msg_size, msg);
}

void svr2LogCallback(
    void* context,
    bool is_enclave,
    const struct tm* t,
    long usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message);

int setUpLoggingInC() {
  return oe_log_set_callback(0, svr2LogCallback);
}

int setSignalOnStack(int signal) {
  int ret = 0;
  struct sigaction action = {0};
  if (0 != (ret = sigaction(signal, 0, &action))) { return ret; }
  action.sa_flags |= SA_ONSTACK;
  if (0 != (ret = sigaction(signal, &action, 0))) { return ret; }
  return 0;
}
*/
import "C"

import (
	"fmt"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/signalapp/svr2/logger"
	"github.com/signalapp/svr2/peerid"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

type EnclaveType int

const (
	MESSAGE_BUFFER_SIZE             = 100
	PRODUCTION          EnclaveType = 0
	SIMULATED           EnclaveType = C.OE_ENCLAVE_FLAG_SIMULATE
)

type SGX struct {
	ptr            *C.struct__oe_enclave
	mu             sync.RWMutex // lock for enclave
	msgSendOutputs chan *pb.EnclaveMessage
	pid            peerid.PeerID
}

var sgxSingleton SGX

// OpenEnclaveError is an error that wraps an oe_result_t.
type OpenEnclaveError C.oe_result_t

// Error implements error.
func (c OpenEnclaveError) Error() string {
	return fmt.Sprintf("error calling enclave: %d==0x%x %s", uint(c), uint(c), C.GoString(C.oe_result_str(C.oe_result_t(c))))
}

// ReturnedError is an error that wraps a SVR2 error.
type ReturnedError C.int

// Error implements error.
func (r ReturnedError) Error() string {
	return fmt.Sprintf("error returned from enclave: %d", uint(r))
}

// Instance returns a live, singleton enclave object that wraps the actual SGX interface.
func SGXEnclave() *SGX { return &sgxSingleton }

var setLoggingOnce sync.Once
var testSGXInterface Enclave = &sgxSingleton

func setUpLogging() {
	if C.OE_OK != C.setUpLoggingInC() {
		panic("setup of logging failed")
	}
}

func (s *SGX) PID() peerid.PeerID {
	return s.pid
}

func (s *SGX) OutputMessages() <-chan *pb.EnclaveMessage {
	return s.msgSendOutputs
}

// The channel guarantees that messages are sent in the order that the enclave sends them.
// Init intializes the enclave.
// [path] is the path to file containing the compiled enclave object to run.
// [config] is the enclave configuration to use.
//
// Init returns a channel of messages that are written to the host by the enclave.
// It's up to the caller to empty and process these messages; failing to do so
// will eventually block the enclave, as the buffer (size MESSAGE_BUFFER_SIZE)
// fills.  The channel will be closed as part of Close(), once the enclave has
// been fully shut down.
//
// The channel guarantees that messages are sent in the order that the enclave sends them.
func (s *SGX) Init(path string, config *pb.InitConfig) (returnedError error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pid peerid.PeerID
	if s.ptr != nil {
		return fmt.Errorf("enclave already initiated")
	}
	setLoggingOnce.Do(setUpLogging)

	var typ EnclaveType = PRODUCTION
	if config.GroupConfig.Simulated {
		typ = SIMULATED
	}

	config.InitialTimestampUnixSecs = uint64(time.Now().Unix())
	configBytes, err := proto.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling config proto: %v", err)
	}
	s.msgSendOutputs = make(chan *pb.EnclaveMessage, MESSAGE_BUFFER_SIZE)
	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))
	if err := C.oe_create_svr2_enclave(pathC, C.OE_ENCLAVE_TYPE_SGX, C.OE_ENCLAVE_FLAG_DEBUG_AUTO|C.uint(typ), nil, 0, &s.ptr); err != C.OE_OK {
		return OpenEnclaveError(err)
	}
	if s.ptr == nil {
		panic("got nil s.ptr")
	}
	defer func() {
		if returnedError != nil {
			s.Close()
		}
	}()

	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&configBytes))
	var ret C.int
	if oeErr := C.svr2_init(s.ptr, &ret, C.ulong(hdr.Len), (*C.uchar)(unsafe.Pointer(hdr.Data)), (*C.uchar)(unsafe.Pointer(&pid[0]))); oeErr != 0 {
		return OpenEnclaveError(oeErr)
	} else if ret != 0 {
		return ReturnedError(ret)
	}
	s.pid = pid

	// Go requires that signal handlers use SA_ONSTACK, but OpenEnclave sets up some
	// signal handlers without this flag.  Reset them.
	// Signals taken from OpenEnclave's host/sgx/linux/exception.c
	for _, signal := range []C.int{C.SIGBUS, C.SIGFPE, C.SIGILL, C.SIGSEGV, C.SIGTRAP, C.SIGHUP, C.SIGABRT, C.SIGALRM, C.SIGPIPE, C.SIGPOLL, C.SIGUSR1, C.SIGUSR2} {
		if r := C.setSignalOnStack(signal); r != 0 {
			return fmt.Errorf("setting onstack for signal %d failed: %d", signal, r)
		}
	}

	return nil
}

// SendMessage sends a message to the running enclave.  Messages generated by
// the enclave during the lifetime of this call will be made available on the
// channel provided by Init.
func (s *SGX) SendMessage(msgPB *pb.UntrustedMessage) error {
	msg, err := proto.Marshal(msgPB)
	if err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&msg))
	var ret C.int
	if oeErr := C.svr2_input_message(s.ptr, &ret, C.ulong(hdr.Len), (*C.uchar)(unsafe.Pointer(hdr.Data))); oeErr != 0 {
		return OpenEnclaveError(oeErr)
	} else if ret != 0 {
		return ReturnedError(ret)
	}
	return nil
}

// Close terminates and releases resources for the enclave.
func (s *SGX) Close() {
	logger.Errorf("Closing SGX")
	s.mu.Lock()
	defer s.mu.Unlock()
	C.oe_terminate_enclave(s.ptr)
	s.ptr = nil
	close(s.msgSendOutputs)
	s.msgSendOutputs = nil
}

// receiveMessage is called by svr2_output_message during svr2_input_message calls.
func receiveMessage(buf []byte) {
	var msg pb.EnclaveMessage
	if err := proto.Unmarshal(buf, &msg); err != nil {
		logger.Errorf("This is a severe bug. Could not unmarshal a message from the enclave. dropping : %v", err)
		return
	}
	// Check the precondition that the mainThread lock should be locked already.
	sgxSingleton.mu.RLock()
	sgxSingleton.msgSendOutputs <- &msg
	sgxSingleton.mu.RUnlock()
}
