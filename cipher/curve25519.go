package cipher

import (
	"bytes"
	"io"

	"github.com/mutecomm/mute/log"
	"golang.org/x/crypto/curve25519"
)

// Curve25519Key holds a Curve25519 key pair.
type Curve25519Key struct {
	publicKey  *[32]byte
	privateKey *[32]byte
}

// Curve25519Generate generates a new Curve25519 key pair.
func Curve25519Generate(rand io.Reader) (*Curve25519Key, error) {
	var c Curve25519Key
	c.privateKey = new([32]byte)
	if _, err := io.ReadFull(rand, c.privateKey[:]); err != nil {
		return nil, err
	}
	c.publicKey = new([32]byte)
	curve25519.ScalarBaseMult(c.publicKey, c.privateKey)
	return &c, nil
}

// PublicKey returns the public key of an curve25519Key.
func (c *Curve25519Key) PublicKey() *[32]byte {
	return c.publicKey
}

// PrivateKey returns the private key of an curve25519Key.
func (c *Curve25519Key) PrivateKey() *[32]byte {
	return c.privateKey
}

// SetPublicKey sets the public key of curve25519Key to key.
// SetPublicKey returns an error, if len(key) != 32.
func (c *Curve25519Key) SetPublicKey(key []byte) error {
	if len(key) != 32 {
		return log.Errorf("cipher: Curve25519Key.SetPublicKey(): len(key) = %d != 32", len(key))
	}
	c.publicKey = new([32]byte)
	copy(c.publicKey[:], key)
	return nil
}

// SetPrivateKey sets the private key of curve25519Key to key.
// SetPrivateKey returns an error, if len(key) != 32.
func (c *Curve25519Key) SetPrivateKey(key []byte) error {
	if len(key) != 32 {
		return log.Errorf("cipher: Curve25519Key.SetPrivateKey(): len(key) = %d != 32", len(key))
	}
	c.privateKey = new([32]byte)
	copy(c.privateKey[:], key)
	return nil
}

// ECDH computes a Diffie-Hellman (DH) key exchange over the elliptic curve (EC)
// curve25519. If ownPublicKey is given it is used to check for the key
// reflection attack. Otherwise it is derived from privateKey.
func ECDH(privateKey, peersPublicKey, ownPublicKey *[32]byte) (*[32]byte, error) {
	var (
		sharedKey [32]byte
		pubKey    []byte
	)
	// check mandatory key length
	if privateKey == nil {
		return nil, log.Error("cipher: curve25519.ECDH(): privateKey == nil")
	}
	if peersPublicKey == nil {
		return nil, log.Error("cipher: curve25519.ECDH(): peersPublicKey == nil")
	}
	// check for key reflection attack
	if ownPublicKey != nil {
		pubKey = ownPublicKey[:]
	} else {
		var publicKey [32]byte
		curve25519.ScalarBaseMult(&publicKey, privateKey)
		pubKey = publicKey[:]
	}
	if bytes.Equal(pubKey, peersPublicKey[:]) {
		return nil, log.Errorf("cipher: curve25519.ECDH(): publicKey == peersPublicKey")
	}
	// perform Diffie-Hellman key exchange
	curve25519.ScalarMult(&sharedKey, privateKey, peersPublicKey)
	return &sharedKey, nil
}
