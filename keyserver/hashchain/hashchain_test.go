// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hashchain

import (
	"bytes"
	"testing"
)

func TestSplitEntry(t *testing.T) {
	_, typ, _, _, _, _, err := SplitEntry(TestEntry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(typ, []byte{0x01}) {
		t.Error("typ != 0x01")
	}
}
