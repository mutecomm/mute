package nymaddr

import (
	"crypto/aes"
	"crypto/cipher"
)

func encryptNym(key, nym []byte) []byte {
	if len(nym) > (KeySize + 1) {
		nym = nym[:(KeySize + 1)]
	}
	d := make([]byte, (KeySize+1)+1)
	d[0] = byte(len(nym) % (KeySize + 1))                       // first byte contains length of nym
	copy(d[1:], nym)                                            // write nym
	block, _ := aes.NewCipher(key)                              // Keysize is ok, so no error should occur
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize)) // This is not very secure, but good enough since key should change a lot
	stream.XORKeyStream(d, d)
	return d
}

func decryptNym(key, encNym []byte) []byte {
	block, _ := aes.NewCipher(key)                              // Keysize is ok, so no error should occur
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize)) // This is not very secure, but good enough since key should change a lot
	stream.XORKeyStream(encNym, encNym)                         // Decrypt
	l := int(encNym[0])
	return encNym[1 : l+1] // cut nym from cleartext
}
