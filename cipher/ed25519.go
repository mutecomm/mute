// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/ed25519"
	"io"

	"github.com/mutecomm/mute/log"
)

// Ed25519Key holds a Ed25519 key pair.
type Ed25519Key struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// Ed25519Generate generates a new Ed25519 key pair.
func Ed25519Generate(rand io.Reader) (*Ed25519Key, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &Ed25519Key{publicKey, privateKey}, nil
}

// PublicKey returns the public key of an ed25519Key.
func (ed25519Key *Ed25519Key) PublicKey() *[32]byte {
	var pk [32]byte
	copy(pk[:], ed25519Key.publicKey)
	return &pk
}

// PrivateKey returns the private key of an ed25519Key.
func (ed25519Key *Ed25519Key) PrivateKey() *[64]byte {
	var pk [64]byte
	copy(pk[:], ed25519Key.privateKey)
	return &pk
}

// SetPublicKey sets the public key of ed25519Key to key.
// SetPublicKey returns an error, if len(key) != ed25519.PublicKeySize.
func (ed25519Key *Ed25519Key) SetPublicKey(key []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return log.Errorf("cipher: Ed25519Key.SetPublicKey(): len(key) = %d != %d = ed25519.PublicKeySize",
			len(key), ed25519.PublicKeySize)
	}
	var pk [ed25519.PublicKeySize]byte
	ed25519Key.publicKey = pk[:]
	copy(ed25519Key.publicKey, key)
	return nil
}

// SetPrivateKey sets the private key of ed25519Key to key.
// SetPrivateKey returns an error, if len(key) != ed25519.PrivateKeySize.
func (ed25519Key *Ed25519Key) SetPrivateKey(key []byte) error {
	if len(key) != ed25519.PrivateKeySize {
		return log.Errorf("cipher: Ed25519Key.SetPrivateKey(): len(key) = %d != %d = ed25519.PrivateKeySize",
			len(key), ed25519.PrivateKeySize)
	}
	var pk [ed25519.PrivateKeySize]byte
	ed25519Key.privateKey = pk[:]
	copy(ed25519Key.privateKey, key)
	return nil
}

// Sign signs the given message with ed25519Key and returns the signature.
func (ed25519Key *Ed25519Key) Sign(message []byte) []byte {
	sig := ed25519.Sign(ed25519Key.privateKey, message)
	return sig[:]
}

// Verify verifies that the signature sig for message is valid for ed25519Key.
func (ed25519Key *Ed25519Key) Verify(message []byte, sig []byte) bool {
	return ed25519.Verify(ed25519Key.publicKey, message, sig)
}
