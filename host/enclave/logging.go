// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"unsafe"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// #include <time.h>
// #include <stdint.h>
// #include <openenclave/log.h>
// #include "c/svr2_u.h"
import "C"

//export svr2LogCallback
func svr2LogCallback(
	context unsafe.Pointer,
	is_enclave bool,
	t *C.struct_tm,
	usecs C.long,
	level C.oe_log_level_t,
	host_thread_id uint64,
	msg *C.char) {

	var zapLevel zapcore.Level
	switch level {
	case C.OE_LOG_LEVEL_NONE:
		zapLevel = zapcore.ErrorLevel
	case C.OE_LOG_LEVEL_FATAL:
		// use error for fatal, fatal in go means panic
		zapLevel = zapcore.ErrorLevel
	case C.OE_LOG_LEVEL_ERROR:
		zapLevel = zapcore.ErrorLevel
	case C.OE_LOG_LEVEL_WARNING:
		zapLevel = zapcore.WarnLevel
	case C.OE_LOG_LEVEL_INFO:
		zapLevel = zapcore.InfoLevel
	case C.OE_LOG_LEVEL_VERBOSE:
		zapLevel = zapcore.DebugLevel
	case C.OE_LOG_LEVEL_MAX:
		zapLevel = zapcore.DebugLevel
	default:
		zapLevel = zapcore.ErrorLevel
	}

	zap.L().Log(zapLevel, C.GoString(msg),
		zap.Uint64("host_thread", host_thread_id))
}
