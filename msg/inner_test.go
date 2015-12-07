// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"testing"
)

func TestInnerHeaderSize(t *testing.T) {
	t.Parallel()
	ih := newInnerHeader(dataType, false, nil)
	if ih.size() != innerHeaderSize {
		t.Errorf("ih.size() = %d != %d", ih.size(), innerHeaderSize)
	}
}
