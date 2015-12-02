// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/rand"
	"io"
)

// RandReader defines the CSPRNG used in Mute.
//
// TODO: use Fortuna?
var RandReader = rand.Reader

// RandFail is a Reader that doesn't deliver any data
var RandFail = eofReader{}

type eofReader struct{}

func (e eofReader) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

// RandZero is a Reader that always returns 0.
var RandZero = zeroReader{}

type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = 0
	}
	return len(p), nil
}
