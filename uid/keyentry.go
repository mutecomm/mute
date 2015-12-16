// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uid

import (
	"bytes"
	"crypto/sha512"
	"io"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// DefaultCiphersuite defines the default ciphersuite:
//   Static Key Agreement: NaCL
//   Key derivation function: HKDF
//   Symmetric encryption: AES-256 in counter mode
//   Integrity protection: SHA-512 HMAC
//   Signature generation: Ed25519
//   Forward secure key agreement: ECDHE over curve25519
// All valid ciphersuite strings are predefined and contain only upper-case letters.
const DefaultCiphersuite string = "NACL HKDF AES256-CTR SHA512-HMAC ED25519 ECDHE25519"

// A KeyEntry describes a key in Mute.
type KeyEntry struct {
	CIPHERSUITE   string // ciphersuite for which the key may be used. Example: "NACL HKDF AES-CTR256 SHA512-HMAC ED25519 ECDHE25519"
	FUNCTION      string // function for which the key may be used in the ciphersuite. Example: "ECDHE25519"
	HASH          string // SHA512 hash of PUBKEY
	PUBKEY        string // the public key
	curve25519Key *cipher.Curve25519Key
	ed25519Key    *cipher.Ed25519Key
	publicKeySet  bool
	privateKeySet bool
}

// KeyEntryEqual returns a boolean reporting whether a and b have the same
// exported fields.
func KeyEntryEqual(a, b *KeyEntry) bool {
	if a == b {
		return true
	}
	if a.CIPHERSUITE != b.CIPHERSUITE {
		return false
	}
	if a.FUNCTION != b.FUNCTION {
		return false
	}
	if a.HASH != b.HASH {
		return false
	}
	if a.PUBKEY != b.PUBKEY {
		return false
	}
	return true
}

// Verify that the content of KeyEntry is consistent and parseable.
func (ke *KeyEntry) Verify() error {
	// verify CIPHERSUITE
	if ke.CIPHERSUITE != DefaultCiphersuite {
		return log.Errorf("uid: unknown ke.CIPHERSUITE: %s", ke.CIPHERSUITE)
	}
	// verify FUNCTION
	if ke.FUNCTION != "ED25510" && ke.FUNCTION != "ECDHE25519" {
		return log.Errorf("uid: unknown ke.FUNCTION: %s", ke.FUNCTION)
	}
	// verify HASH
	h, err := base64.Decode(ke.HASH)
	if err != nil {
		return log.Errorf("uid: ke.HASH is not parseable: %s", err)
	}
	if len(h) != sha512.Size {
		return log.Errorf("uid: parsed ke.HASH has wrong length: %d", len(h))
	}
	// verify PUBKEY
	pk, err := base64.Decode(ke.PUBKEY)
	if err != nil {
		return log.Errorf("uid: ke.PUBKEY is not parseable: %s", err)
	}
	if len(pk) != 32 {
		return log.Errorf("uid: ke.PUBKEY has wrong length: %d", len(pk))
	}
	// make sure SHA512(PUBKEY) matches HASH
	if !bytes.Equal(cipher.SHA512(pk), h) {
		return log.Errorf("uid: SHA512(ke.PUBKEY) != ke.HASH")
	}
	return nil
}

// InitDHKey initializes the KeyEntry with a key for ECDHE25519.
//
// TODO: InitDHKey has to be separated, should only end up in mutecrypt and
// not in mutekeyd.
func (ke *KeyEntry) InitDHKey(rand io.Reader) error {
	var err error
	ke.CIPHERSUITE = DefaultCiphersuite
	ke.FUNCTION = "ECDHE25519"
	// generate Curve25519 key
	if ke.curve25519Key, err = cipher.Curve25519Generate(rand); err != nil {
		return err
	}
	ke.HASH = base64.Encode(cipher.SHA512(ke.curve25519Key.PublicKey()[:]))
	ke.PUBKEY = base64.Encode(ke.curve25519Key.PublicKey()[:])
	ke.publicKeySet = true
	ke.privateKeySet = true
	return nil
}

// TODO: initSigKey has to be separated, should only end up in mutecrypt and
// not in mutekeyd.
func (ke *KeyEntry) initSigKey(rand io.Reader) error {
	var err error
	ke.CIPHERSUITE = DefaultCiphersuite
	ke.FUNCTION = "ED25519"
	// generate Ed25519 signature key
	if ke.ed25519Key, err = cipher.Ed25519Generate(rand); err != nil {
		return err
	}
	ke.HASH = base64.Encode(cipher.SHA512(ke.ed25519Key.PublicKey()[:]))
	ke.PUBKEY = base64.Encode(ke.ed25519Key.PublicKey()[:])
	ke.publicKeySet = true
	ke.privateKeySet = true
	return nil
}

// PublicKey32 returns the 32-byte public key of KeyEntry.
func (ke *KeyEntry) PublicKey32() *[32]byte {
	if !ke.publicKeySet {
		pubKey, err := base64.Decode(ke.PUBKEY)
		if err != nil {
			panic(log.Critical(err))
		}
		switch ke.FUNCTION {
		case "ECDHE25519":
			if ke.curve25519Key == nil {
				ke.curve25519Key = new(cipher.Curve25519Key)
			}
			ke.curve25519Key.SetPublicKey(pubKey)
		case "ED25519":
			if ke.ed25519Key == nil {
				ke.ed25519Key = new(cipher.Ed25519Key)
			}
			ke.ed25519Key.SetPublicKey(pubKey)
		}
		ke.publicKeySet = true
	}
	switch ke.FUNCTION {
	case "ECDHE25519":
		return ke.curve25519Key.PublicKey()
	case "ED25519":
		return ke.ed25519Key.PublicKey()
	default:
		panic(log.Critical("uid: should not happen"))
	}
}

// PrivateKey32 returns the 32-byte private key of the KeyEntry.
func (ke *KeyEntry) PrivateKey32() *[32]byte {
	if !ke.privateKeySet {
		panic(log.Critical("uid: private key not set"))
	}
	switch ke.FUNCTION {
	case "ECDHE25519":
		return ke.curve25519Key.PrivateKey()
	default:
		panic(log.Critical("uid: wrong private key size"))
	}
}

// PrivateKey64 returns the 64-byte private key of the KeyEntry.
func (ke *KeyEntry) PrivateKey64() *[64]byte {
	if !ke.privateKeySet {
		panic(log.Critical("uid: private key not set"))
	}
	switch ke.FUNCTION {
	case "ED25519":
		return ke.ed25519Key.PrivateKey()
	default:
		panic(log.Critical("uid: wrong private key size"))
	}
}

// setPrivateKey sets the private key of the KeyEntry.
func (ke *KeyEntry) setPrivateKey(key []byte) error {
	var err error
	switch ke.FUNCTION {
	case "ECDHE25519":
		if ke.curve25519Key == nil {
			ke.curve25519Key = new(cipher.Curve25519Key)
		}
		err = ke.curve25519Key.SetPrivateKey(key)
	case "ED25519":
		if ke.ed25519Key == nil {
			ke.ed25519Key = new(cipher.Ed25519Key)
		}
		err = ke.ed25519Key.SetPrivateKey(key)
	default:
		err = log.Error("uid: unknown FUNCTION in KeyEntry")
	}
	if err == nil {
		ke.privateKeySet = true
	}
	return err
}

// SetPrivateKey sets the private key to the given base64 encoded privkey
// string.
func (ke *KeyEntry) SetPrivateKey(privkey string) error {
	key, err := base64.Decode(privkey)
	if err != nil {
		return err
	}
	return ke.setPrivateKey(key)
}
