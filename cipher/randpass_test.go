// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"testing"
)

func TestRandPass(t *testing.T) {
	p1 := RandPass(RandReader)
	p2 := RandPass(RandReader)
	if p1 == p2 {
		t.Fatal("should differ")
	}
}

func TestRandPassPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("should panic")
		}
	}()
	RandPass(RandFail)
}
