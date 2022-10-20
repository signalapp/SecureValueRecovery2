// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package proto

import (
	"fmt"
)

// Error implements the `error` interface on the `Error` enum.
func (e Error) Error() string {
	if str, ok := Error_name[int32(e)]; ok {
		return str
	}
	return fmt.Sprintf("UnknownErrorEnumValue(%d)", int32(e))
}
