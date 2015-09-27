// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"io"

	"github.com/mutecomm/mute/log"
	"golang.org/x/crypto/nacl/box"
)

// NaClBoxKey holds the public and private keys for a NaCl-box.
type NaClBoxKey struct {
	publicKey, privateKey *[32]byte
}

// NaClBoxGenerate generates a new NaClBox key pair.
func NaClBoxGenerate(rand io.Reader) (*NaClBoxKey, error) {
	publicKey, privateKey, err := box.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &NaClBoxKey{publicKey, privateKey}, nil
}

// PublicKey returns the public key of a NaClBox.
func (naClBoxKey *NaClBoxKey) PublicKey() []byte {
	return naClBoxKey.publicKey[:]
}

// SetPublicKey sets the public key of naclbox to key.
// SetPublicKey returns an error, if len(key) != 32.
func (naClBoxKey *NaClBoxKey) SetPublicKey(key []byte) error {
	if len(key) != 32 {
		return log.Errorf("cipher: NaClBoxKey.SetPublicKey(): len(key) != 32")
	}
	naClBoxKey.publicKey = new([32]byte)
	copy(naClBoxKey.publicKey[:], key)
	return nil
}

// PrivateKey returns the private key of a NaClBox.
func (naClBoxKey *NaClBoxKey) PrivateKey() []byte {
	return naClBoxKey.privateKey[:]
}

// SetPrivateKey sets the private key of naclbox to key.
// SetPrivateKey returns an error, if len(key) != 32.
func (naClBoxKey *NaClBoxKey) SetPrivateKey(key []byte) error {
	if len(key) != 32 {
		return log.Errorf("cipher: NaClBoxKey.SetPrivateKey(): len(key) != 32")
	}
	naClBoxKey.privateKey = new([32]byte)
	copy(naClBoxKey.privateKey[:], key)
	return nil
}
