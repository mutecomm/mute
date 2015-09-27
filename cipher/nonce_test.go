// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"testing"
)

func TestNonce(t *testing.T) {
	if bytes.Equal(Nonce(RandReader), Nonce(RandReader)) {
		t.Error("Nonce() == Nonce() -> bingo!")
	}
}

func TestNoncePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("should panic")
		}
	}()
	Nonce(RandFail)
}
