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
