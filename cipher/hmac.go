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
