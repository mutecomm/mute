// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package padding contains helper functions to generate cheap paddings.
package padding

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// Generate generates a new cheap padding of the given length.
func Generate(length int, rand io.Reader) ([]byte, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand, key[:]); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key[:]) // correct key length was set above
	padding := make([]byte, (1+length/aes.BlockSize)*aes.BlockSize)
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(padding, padding)
	return padding[0:length], nil
}
