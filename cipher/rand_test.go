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
