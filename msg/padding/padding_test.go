// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package padding

import (
	"testing"

	"github.com/mutecomm/mute/cipher"
)

func TestGenerate(t *testing.T) {
	if _, err := Generate(100, cipher.RandFail); err == nil {
		t.Error("should fail")
	}
	_, err := Generate(100, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
}
