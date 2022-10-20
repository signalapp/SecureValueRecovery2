// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"reflect"
	"unsafe"
)

// #include <stdint.h>
import "C"

//export svr2OutputMessageGoCallback
func svr2OutputMessageGoCallback(size C.size_t, msg *C.uchar) {
	var msgSlice []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&msgSlice))
	hdr.Len = int(size)
	hdr.Cap = int(size)
	hdr.Data = uintptr(unsafe.Pointer(msg))
	receiveMessage(msgSlice)
}
