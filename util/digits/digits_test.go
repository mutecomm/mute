// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package digits

import (
	"testing"
)

func TestCount(t *testing.T) {
	if Count(0) != 1 {
		t.Error("Count(0) != 1")
	}
	if Count(9) != 1 {
		t.Error("Count(9) != 1")
	}
	if Count(10) != 2 {
		t.Error("Count(10) != 2")
	}
	if Count(100) != 3 {
		t.Error("Count(100) != 3")
	}
	if Count(1000) != 4 {
		t.Error("Count(1000) != 4")
	}
	if Count(10000) != 5 {
		t.Error("Count(10000) != 5")
	}
	if Count(100000) != 6 {
		t.Error("Count(100000) != 6")
	}
	if Count(1000000) != 7 {
		t.Error("Count(1000000) != 7")
	}
	if Count(10000000) != 8 {
		t.Error("Count(10000000) != 8")
	}
	if Count(100000000) != 9 {
		t.Error("Count(100000000) != 9")
	}
	if Count(1000000000) != 10 {
		t.Error("Count(1000000000) != 10")
	}
	if Count(10000000000) != 11 {
		t.Error("Count(10000000000) != 11")
	}
	if Count(100000000000) != 12 {
		t.Error("Count(100000000000) != 12")
	}
	if Count(1000000000000) != 13 {
		t.Error("Count(1000000000000) != 13")
	}
	if Count(10000000000000) != 14 {
		t.Error("Count(10000000000000) != 14")
	}
	if Count(100000000000000) != 15 {
		t.Error("Count(100000000000000) != 15")
	}
	if Count(1000000000000000) != 16 {
		t.Error("Count(1000000000000000) != 16")
	}
	if Count(10000000000000000) != 17 {
		t.Error("Count(10000000000000000) != 17")
	}
	if Count(100000000000000000) != 18 {
		t.Error("Count(100000000000000000) != 18")
	}
	if Count(1000000000000000000) != 19 {
		t.Error("Count(1000000000000000000) != 19")
	}
	if Count(18446744073709551615) != 20 {
		t.Error("Count(18446744073709551615) != 20")
	}
}
