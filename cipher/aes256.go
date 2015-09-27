// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/mutecomm/mute/log"
)

// AES256CBCEncrypt encrypts the given plaintext with AES-256 in CBC mode.
// The supplied key must be 32 bytes long.
// The returned ciphertext is prepended by a randomly generated IV.
func AES256CBCEncrypt(key, plaintext []byte, rand io.Reader) (ciphertext []byte) {
	if len(key) != 32 {
		panic(log.Critical("cipher: AES-256 key is not 32 bytes long"))
	}
	block, _ := aes.NewCipher(key) // correct key length was enforced above

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic(log.Critical("cipher: plaintext is not a multiple of the block size"))
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand, iv)
	if err != nil {
		panic(log.Critical(err))
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return
}

// AES256CBCDecrypt decrypts the given ciphertext with AES-256 in CBC mode and
// returns the resulting plaintext. The supplied key must be 32 bytes long and
// the ciphertext must be prepended by the corresponding IV.
func AES256CBCDecrypt(key, ciphertext []byte) (plaintext []byte) {
	if len(key) != 32 {
		panic(log.Critical("cipher: AES-256 key is not 32 bytes long"))
	}
	block, _ := aes.NewCipher(key) // correct key length was enforced above

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic(log.Critical("cipher: ciphertext too short"))
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	plaintext = make([]byte, len(ciphertext))

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic(log.Critical("cipher: ciphertext is not a multiple of the block size"))
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plaintext, ciphertext)

	return
}

// AES256CTREncrypt encrypts the given plaintext with AES-256 in CTR mode.
// The supplied key must be 32 bytes long.
// The returned ciphertext is prepended by a randomly generated IV.
func AES256CTREncrypt(key, plaintext []byte, rand io.Reader) (ciphertext []byte) {
	if len(key) != 32 {
		panic(log.Critical("cipher: AES-256 key is not 32 bytes long"))
	}
	block, _ := aes.NewCipher(key) // correct key length was enforced above

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand, iv)
	if err != nil {
		panic(log.Critical(err))
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return
}

// AES256CTRDecrypt decrypts the given ciphertext with AES-256 in CTR mode and
// returns the resulting plaintext. The supplied key must be 32 bytes long and
// the ciphertext must be prepended by the corresponding IV.
func AES256CTRDecrypt(key, ciphertext []byte) (plaintext []byte) {
	if len(key) != 32 {
		panic(log.Critical("cipher: AES-256 key is not 32 bytes long"))
	}
	block, _ := aes.NewCipher(key) // correct key length was enforced above

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic(log.Critical("cipher: ciphertext too short"))
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	plaintext = make([]byte, len(ciphertext))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return
}

// AES256CTRStream creates a new AES-256 stream in CTR mode.
// The supplied key must be 32 bytes long and the iv 16 bytes.
func AES256CTRStream(key, iv []byte) cipher.Stream {
	if len(key) != 32 {
		panic(log.Critical("cipher: AES-256 key is not 32 bytes long"))
	}
	if len(iv) != 16 {
		panic(log.Critical("cipher: AES-256 IV is not 16 bytes long"))
	}
	block, _ := aes.NewCipher(key) // correct key length was enforced above
	return cipher.NewCTR(block, iv)
}
