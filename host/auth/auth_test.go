// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/signalapp/svr2/util"
)

func TestAuthWorks(t *testing.T) {
	a := &auth{
		secret:     []byte{1, 2, 3, 4, 5},
		clock:      util.TestAt(time.Unix(10000, 0)),
		expiration: 3600 * time.Second,
	}
	for _, test := range []struct{ user, pass string }{
		{user: "12345", pass: "10000:8b2df41718f48f312c6d"},
		{user: "12345", pass: "13600:fb1e57e272683fb785b1"},
		{user: "12345", pass: "6400:614c7129a946e79c83ed"},
		{user: "123456", pass: "10000:9a08d531879caa2a81f0"},
		{user: "wizzle", pass: a.PassFor("wizzle")},
	} {
		t.Logf("%+v", test)
		if err := a.Check(test.user, test.pass); err != nil {
			t.Errorf("expected check success, got error: %v", err)
		}
	}

	validPass := []byte{0x8b, 0x2d, 0xf4, 0x17, 0x18, 0xf4, 0x8f, 0x31, 0x2c, 0x6d}
	for i := 0; i < len(validPass); i++ {
		for j := 0; j < 8; j++ {
			b := make([]byte, len(validPass))
			copy(b, validPass)
			b[i] ^= 1 << j
			badPass := fmt.Sprintf("10000:%x", b)
			if err := a.Check("12345", badPass); err == nil {
				t.Errorf("bitflipped pass, want error got success: valid=%x ours=%q", validPass, badPass)
			}
		}
	}
}
