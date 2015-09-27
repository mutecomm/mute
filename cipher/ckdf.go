// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/sha512"
)

// CKDF (Cheap Key Derivation Function) generates two keys k1 and k2 from the
// given nonce. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/ciphers.md#ckdf-cheap-key-derivation-function
//
// TODO: review!
func CKDF(nonce []byte) (k1, k2 []byte) {
	// a  = SHA512(key)
	a := SHA512(nonce)
	hashsize := sha512.Size

	// a1 = a[0, (hashsize / 2)] | a[0, (hashsize / 2)]
	a1 := make([]byte, hashsize)
	copy(a1, a[:hashsize/2])
	copy(a1[hashsize/2:], a[:hashsize/2])

	// a2 = a[(hashsize / 2), hashsize] | a[(hashsize / 2), hashsize]
	a2 := make([]byte, hashsize)
	copy(a2, a[hashsize/2:])
	copy(a2[hashsize/2:], a[hashsize/2:])

	// k1 = SHA512( a1 ^ [0x5c * hashsize] | SHA512( a2 ^ [0x36 * hashsize] ))
	pad1 := make([]byte, hashsize*2)
	for i := 0; i < hashsize; i++ {
		pad1[i] = a1[i] ^ 0x5c
	}
	for i := 0; i < hashsize; i++ {
		pad1[hashsize+i] = a2[i] ^ 0x36
	}
	copy(pad1[hashsize:], SHA512(pad1[hashsize:]))
	k1 = SHA512(pad1)

	// k2 = SHA512( a2 ^ [0x5c * hashsize] | SHA512( a1 ^ [0x36 * hashsize] ))
	pad2 := make([]byte, hashsize*2)
	for i := 0; i < hashsize; i++ {
		pad2[i] = a2[i] ^ 0x5c
	}
	for i := 0; i < hashsize; i++ {
		pad2[hashsize+i] = a1[i] ^ 0x36
	}
	copy(pad2[hashsize:], SHA512(pad2[hashsize:]))
	k2 = SHA512(pad2)

	return
}
