// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package proto

import (
	"testing"
)

func TestError(t *testing.T) {
	var e error = Error_Core_NoInit
	if got, want := e.Error(), "Core_NoInit"; got != want {
		t.Errorf("got %q want %q", got, want)
	}

	e = Error(-1)
	if got, want := e.Error(), "UnknownErrorEnumValue(-1)"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
