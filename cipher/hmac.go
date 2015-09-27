// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/hmac"
	"crypto/sha512"
)

// HMAC computes the keyed-hash message authentication code of buffer with the
// given key.
func HMAC(key, buffer []byte) []byte {
	hash := hmac.New(sha512.New, key)
	hash.Write(buffer)
	return hash.Sum(make([]byte, 0, sha512.Size))
}
