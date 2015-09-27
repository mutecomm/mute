// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"io"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// RandPass returns a random 256-bit password in base64 encoding.
func RandPass(rand io.Reader) string {
	var pass = make([]byte, 32)
	if _, err := io.ReadFull(rand, pass); err != nil {
		panic(log.Critical(err))
	}
	return base64.Encode(pass)
}
