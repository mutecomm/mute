// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes256

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/mutecomm/mute/cipher"
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
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
}

func TestAES256(t *testing.T) {
	ciphertext := CBCEncrypt(key, []byte(secret), rand.Reader)
	plaintext := string(CBCDecrypt(key, ciphertext))
	if plaintext != secret {
		t.Error("CBC: plaintext != secret")
	}

	ciphertext = CTREncrypt(key, []byte(secret), rand.Reader)
	plaintext = string(CTRDecrypt(key, ciphertext))
	if plaintext != secret {
		t.Error("CTR: plaintext != secret")
	}
}

func TestAES256Stream(t *testing.T) {
	stream := CTRStream(key, iv)
	ciphertext := make([]byte, len(secret))
	stream.XORKeyStream(ciphertext, []byte(secret))
	stream = CTRStream(key, iv)
	plaintext := make([]byte, len(secret))
	stream.XORKeyStream(plaintext, ciphertext)
	if string(plaintext) != secret {
		t.Error("CTRStream: plaintext != secret")
	}
}

func shouldPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Fatal("should panic")
	}
}

func TestAESCBCEncryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	CBCEncrypt(shortKey, []byte(secret), rand.Reader)
}

func TestAESCBCEncryptShortPlaintext(t *testing.T) {
	defer shouldPanic(t)
	CBCEncrypt(key, []byte(shortSecret), rand.Reader)
}

func TestAESCBCEncryptRandFail(t *testing.T) {
	defer shouldPanic(t)
	CBCEncrypt(key, []byte(secret), cipher.RandFail)
}

func TestAESCBCDecryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	CBCDecrypt(shortKey, []byte(secret))
}

func TestAESCBCDecryptShortCiphertext(t *testing.T) {
	defer shouldPanic(t)
	CBCDecrypt(key, []byte(shortSecret))
}

func TestAESCBCDecryptMultCiphertext(t *testing.T) {
	defer shouldPanic(t)
	CBCDecrypt(key, []byte(multCiphertext))
}

func TestAESCTREncryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	CTREncrypt(shortKey, []byte(secret), rand.Reader)
}

func TestAESCTREncryptRandFail(t *testing.T) {
	defer shouldPanic(t)
	CTREncrypt(key, []byte(secret), cipher.RandFail)
}

func TestAESCTRDecryptShortKey(t *testing.T) {
	defer shouldPanic(t)
	CTRDecrypt(shortKey, []byte(secret))
}

func TestAESCTRDecryptShortCiphertext(t *testing.T) {
	defer shouldPanic(t)
	CTRDecrypt(key, []byte(shortSecret))
}

func TestAESCTRStreamShortKey(t *testing.T) {
	defer shouldPanic(t)
	_ = CTRStream(shortKey, iv)
}

func TestAESCTRStreamShortIV(t *testing.T) {
	defer shouldPanic(t)
	_ = CTRStream(key, shortIV)
}
