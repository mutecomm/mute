// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mixcrypt implements the client-mix-client message encryption.
package mixcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
)

// genNonce generates a nonce
func genNonce() (nonce *[KeySize]byte, err error) {
	nonce = new([KeySize]byte)
	if _, err = io.ReadFull(Rand, nonce[:]); err != nil {
		return nil, err
	}
	return nonce, nil
}

// CalculateSharedSecret calculates a shared secret from the given parameters. If myPrivateKey is nil, it will
// return only nils. If Nonce is nil, a nonce will be created
func CalculateSharedSecret(peerPublicKey, myPrivateKey, nonceIn *[KeySize]byte) (secret, nonceOut *[KeySize]byte) {
	var err error
	if myPrivateKey == nil || peerPublicKey == nil {
		return nil, nil
	}
	if nonceIn == nil {
		nonceOut, err = genNonce()
		if err != nil {
			return nil, nil
		}
	} else {
		nonceOut = nonceIn
	}
	secretOne := new([KeySize]byte)
	curve25519.ScalarMult(secretOne, myPrivateKey, peerPublicKey)
	return ExpandSecret(nonceOut[:], secretOne[:]), nonceOut
}

// ExpandSecret expands a nonce/key for multi-use encryption (unique nonces, constant keys)
func ExpandSecret(nonce, key []byte) *[KeySize]byte {
	var secretS []byte
	hm := hmac.New(sha256.New, key)
	hm.Write(nonce[:])
	secretS = hm.Sum(secretS)
	secret := new([KeySize]byte)
	copy(secret[:], secretS)
	return secret
}

func getGCM(key []byte) (cipher.AEAD, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcmMode, err := cipher.NewGCM(blockCipher)
	return gcmMode, err
}

// GCMDecrypt data with AES-GCM
func GCMDecrypt(nonce, key, encryptedData []byte) ([]byte, error) {
	gcmMode, err := getGCM(key)
	if err != nil {
		return nil, err
	}
	t, err := gcmMode.Open(nil, nonce[:gcmMode.NonceSize()], encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GCMEncrypt data with AES-GCM
func GCMEncrypt(nonce, key, cleartextData []byte) ([]byte, error) {
	gcmMode, err := getGCM(key)
	if err != nil {
		return nil, err
	}
	return gcmMode.Seal(nil, nonce[:gcmMode.NonceSize()], cleartextData, nil), nil
}

// Encrypt an envelope (Client-Mix) with CURVE25519-AES-GCM
func Encrypt(peerPublicKey, myPrivateKey *[KeySize]byte, cleartextData []byte) ([]byte, error) {
	var myPublicKey [KeySize]byte
	if myPrivateKey == nil {
		myPrivateKey = new([KeySize]byte)
		_, err := io.ReadFull(Rand, myPrivateKey[:])
		if err != nil {
			return nil, err
		}
	}
	secret, nonce := CalculateSharedSecret(peerPublicKey, myPrivateKey, nil)
	if secret == nil {
		return nil, ErrNoKeys
	}
	curve25519.ScalarBaseMult(&myPublicKey, myPrivateKey)
	encData, err := GCMEncrypt(nonce[:], secret[:], cleartextData)
	if err != nil {
		return nil, err
	}
	encData2 := make([]byte, KeySize*3+len(encData))
	copy(encData2[0:KeySize], peerPublicKey[:])
	copy(encData2[KeySize:KeySize*2], myPublicKey[:])
	copy(encData2[KeySize*2:KeySize*3], nonce[:])
	copy(encData2[KeySize*3:], encData)
	return encData2, nil
}

// Decrypt an envelope (Client-Mix) with CURVE25519-AES-GCM
func Decrypt(lookupKey KeyFunc, encryptedData []byte) ([]byte, error) {
	var peerPublicKey, myPublicKey, nonce [KeySize]byte
	if len(encryptedData) <= KeySize*3 {
		return nil, ErrTooShort
	}
	copy(myPublicKey[:], encryptedData[0:KeySize])
	copy(peerPublicKey[:], encryptedData[KeySize:KeySize*2])
	copy(nonce[:], encryptedData[KeySize*2:KeySize*3])
	myPrivateKey := lookupKey(&myPublicKey)
	if myPrivateKey == nil {
		return nil, ErrNoKeys
	}
	secret, nonce2 := CalculateSharedSecret(&peerPublicKey, myPrivateKey, &nonce)
	if secret == nil {
		return nil, ErrNoKeys
	}
	return GCMDecrypt(nonce2[:], secret[:], encryptedData[KeySize*3:])
}
