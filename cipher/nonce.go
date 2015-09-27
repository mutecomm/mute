// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"io"

	"github.com/mutecomm/mute/log"
)

// Nonce generates a random nonce.
func Nonce(rand io.Reader) []byte {
	var b = make([]byte, 8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		panic(log.Critical(err))
	}
	return b
}
