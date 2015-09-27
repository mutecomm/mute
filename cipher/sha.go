// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

// SHA1 computes the SHA1 hash of the given buffer.
// In Mute SHA1 is only used for tokens.
func SHA1(buffer []byte) []byte {
	hash := sha1.New()
	hash.Write(buffer)
	return hash.Sum(make([]byte, 0, sha1.Size))
}

// SHA256 computes the SHA256 hash of the given buffer.
// In Mute SHA256 is only used for hash chain operations.
func SHA256(buffer []byte) []byte {
	hash := sha256.New()
	hash.Write(buffer)
	return hash.Sum(make([]byte, 0, sha256.Size))
}

// SHA512 computes the SHA512 hash of the given buffer.
// In Mute SHA512 is used for everything except tokens and hash chain
// operations. For example, key material is hashed with SHA512 and message
// authentication uses SHA512.
func SHA512(buffer []byte) []byte {
	hash := sha512.New()
	hash.Write(buffer)
	return hash.Sum(make([]byte, 0, sha512.Size))
}
