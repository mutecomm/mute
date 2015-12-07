// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package padding

import (
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
)

func TestGenerateFail(t *testing.T) {
	t.Parallel()
	if _, err := Generate(32, cipher.RandFail); err == nil {
		t.Error("should fail")
	}
	if _, err := Generate(33, cipher.RandFail); err == nil {
		t.Error("should fail")
	}
}

func TestGenerateZero(t *testing.T) {
	t.Parallel()
	padding, err := Generate(0, cipher.RandZero)
	if err != nil {
		t.Fatal(err)
	}
	if base64.Encode(padding) != "" {
		t.Error("wrong padding")
	}
}

func TestGenerateShort(t *testing.T) {
	t.Parallel()
	padding, err := Generate(32, cipher.RandZero)
	if err != nil {
		t.Fatal(err)
	}
	if base64.Encode(padding) != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Error("wrong padding")
	}
}

func TestGenerateLong(t *testing.T) {
	t.Parallel()
	padding, err := Generate(33, cipher.RandZero)
	if err != nil {
		t.Fatal(err)
	}
	if base64.Encode(padding) != "3JXAeKJAiYmtSKIUkoQgh1MPivvHRTa5qWO08cTLc4vO" {
		t.Error("wrong padding")
	}
}
