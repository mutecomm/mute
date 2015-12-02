// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"testing"
)

func TestRandFail(t *testing.T) {
	b := make([]byte, 32)
	if _, err := RandFail.Read(b); err == nil {
		t.Fatal("should fail")
	}
}

func TestRandZero(t *testing.T) {
	b := make([]byte, 32)
	n, err := RandZero.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Error("n != 32")
	}
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			t.Errorf("b[%d] != 0", i)
		}
	}
}
