// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package padding

import (
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
)

func TestGenerate(t *testing.T) {
	if _, err := Generate(23, cipher.RandFail); err == nil {
		t.Error("should fail")
	}
	padding, err := Generate(23, cipher.RandZero)
	if err != nil {
		t.Fatal(err)
	}
	if base64.Encode(padding) != "3JXAeKJAiYmtSKIUkoQgh1MPivvHRTY=" {
		t.Error("wrong padding")
	}
}
