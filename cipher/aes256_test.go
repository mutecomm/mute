// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"io"
	"testing"
)

var (
	secret         = "this is a secret"
	key            = make([]byte, 32)
	iv             = make([]byte, 16)
	shortSecret    = "too short"
	shortKey       = make([]byte, 31)
	shortIV        = make([]byte, 15)
	multCiphertext = "this ciphertext is not a multiple"
)

func init() {
	if _, err := io.ReadFull(RandReader, key); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(RandReader, iv); err != nil {
		panic(err)
	}
}

func TestAES256(t *testing.T) {
	ciphertext := AES256CBCEncrypt(key, []byte(secret), RandReader)
	plaintext := string(AES256CBCDecrypt(key, ciphertext))
	if plaintext != secret {
		t.Error("AES256CBC: plaintext != secret")
	}

	ciphertext = AES256CTREncrypt(key, []byte(secret), RandReader)
	plaintext = string(AES256CTRDecrypt(key, ciphertext))
	if plaintext != secret {
		t.Error("AES256CTR: plaintext != secret")
	}
}

func TestAES256Stream(t *testing.T) {
	stream := AES256CTRStream(key, iv)
	ciphertext := make([]byte, len(secret))
	stream.XORKeyStream(ciphertext, []byte(secret))
	stream = AES256CTRStream(key, iv)
	plaintext := make([]byte, len(secret))
	stream.XORKeyStream(plaintext, ciphertext)
	if string(plaintext) != secret {
		t.Error("AES256CTRStream: plaintext != secret")
	}
}

func shouldPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Fatal("should panic")
	}
}

func TestAESCBCEncryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCEncrypt(shortKey, []byte(secret), RandReader)
}

func TestAESCBCEncryptShortPlaintext(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCEncrypt(key, []byte(shortSecret), RandReader)
}

func TestAESCBCEncryptRandFail(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCEncrypt(key, []byte(secret), RandFail)
}

func TestAESCBCDecryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCDecrypt(shortKey, []byte(secret))
}

func TestAESCBCDecryptShortCiphertext(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCDecrypt(key, []byte(shortSecret))
}

func TestAESCBCDecryptMultCiphertext(t *testing.T) {
	defer shouldPanic(t)
	AES256CBCDecrypt(key, []byte(multCiphertext))
}

func TestAESCTREncryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	AES256CTREncrypt(shortKey, []byte(secret), RandReader)
}

func TestAESCTREncryptRandFail(t *testing.T) {
	defer shouldPanic(t)
	AES256CTREncrypt(key, []byte(secret), RandFail)
}

func TestAESCTRDecryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	AES256CTRDecrypt(shortKey, []byte(secret))
}

func TestAESCTRDecryptShortCiphertext(t *testing.T) {
	defer shouldPanic(t)
	AES256CTRDecrypt(key, []byte(shortSecret))
}

func TestAESCTRStreamShortKey(t *testing.T) {
	defer shouldPanic(t)
	_ = AES256CTRStream(shortKey, iv)
}

func TestAESCTRStreamShortIV(t *testing.T) {
	defer shouldPanic(t)
	_ = AES256CTRStream(key, shortIV)
}
