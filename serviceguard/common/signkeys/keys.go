// Package signkeys implements key generation and verification methods for keys suitable for blind signature creation
package signkeys

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/util/times"
	"github.com/ronperry/cryptoedge/eccutil"
)

var (
	// ErrNoSigner is returned if a generator is missing a private key for signing its keys
	ErrNoSigner = errors.New("keygen: No signer")
)

const (
	// DefaultExpireTime is the duration for which a key is considered valid
	DefaultExpireTime = 2592000 // one month
)

const (
	// KeyIDSize is the size of a keyID
	KeyIDSize = sha256.Size
)

// KeyGenerator implements a signing key generator and a verifyer
type KeyGenerator struct {
	Curve      *eccutil.Curve // Curve and hash for all keys
	ExpireTime int64          // Expire duration to set on generation
	Usage      string         // The key usage type
	PublicKey  *[ed25519.PublicKeySize]byte
	PrivateKey *[ed25519.PrivateKeySize]byte
}

// New returns a new key generator. The Usage and URL of the generator must be explicitely set
func New(curve func() elliptic.Curve, rand io.Reader, hash func([]byte) []byte) *KeyGenerator {
	kg := new(KeyGenerator)
	kg.Curve = eccutil.SetCurve(curve, rand, hash)
	kg.ExpireTime = DefaultExpireTime
	return kg
}

// KeyPair represents a keypair
type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey []byte // Private key
}

// PublicKey represents the public components of a key
type PublicKey struct {
	KeyID     [KeyIDSize]byte             // The KeyID (hash) of this key
	PublicKey eccutil.Point               // Public key of PrivateKey
	Expire    int64                       // Last unixtime for which this key is usable for verification
	Usage     string                      // The usage for the key
	Signer    [ed25519.PublicKeySize]byte // The signer
	Signature [ed25519.SignatureSize]byte // Signature of key
}

// PublicKeyMarshal is an intermediate representation of a public key to fix limitations of ASN1
type PublicKeyMarshal struct {
	KeyID                  []byte
	PublicKeyX, PublicKeyY []byte
	Expire                 int64
	Usage                  string
	Signer                 []byte
	Signature              []byte
}

// Marshal a public key to ASN1
func (pk PublicKey) Marshal() ([]byte, error) {
	pkm := PublicKeyMarshal{
		KeyID:      pk.KeyID[:],
		PublicKeyX: pk.PublicKey.X.Bytes(),
		PublicKeyY: pk.PublicKey.Y.Bytes(),
		Expire:     pk.Expire,
		Usage:      pk.Usage,
		Signer:     pk.Signer[:],
		Signature:  pk.Signature[:],
	}
	return asn1.Marshal(pkm)
}

// Unmarshal fills the public key with d
func (pk *PublicKey) Unmarshal(d []byte) (*PublicKey, error) {
	if pk == nil {
		pk = new(PublicKey)
	}
	pkm := new(PublicKeyMarshal)
	_, err := asn1.Unmarshal(d, pkm)
	if err != nil {
		return nil, err
	}
	pk.PublicKey.X = new(big.Int).SetBytes(pkm.PublicKeyX)
	pk.PublicKey.Y = new(big.Int).SetBytes(pkm.PublicKeyY)
	pk.Expire = pkm.Expire
	pk.Usage = pkm.Usage
	copy(pk.KeyID[:], pkm.KeyID)
	copy(pk.Signature[:], pkm.Signature)
	copy(pk.Signer[:], pkm.Signer)
	return pk, nil
}

// Verify verifies a public key using SignaturePublicKey
func (pk PublicKey) Verify(SignaturePublicKey *[ed25519.PublicKeySize]byte) bool {
	tcalc := pk.CalcKeyID()
	if tcalc != pk.KeyID {
		return false
	}
	return ed25519.Verify(SignaturePublicKey, tcalc[:], &pk.Signature)
}

// CalcKeyID returns the sha256 of the key components
func (pk *PublicKey) CalcKeyID() [sha256.Size]byte {
	var keyIDImage []byte
	keyIDImage = append(keyIDImage, pk.PublicKey.X.Bytes()...)
	keyIDImage = append(keyIDImage, pk.PublicKey.Y.Bytes()...)
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(pk.Expire))
	keyIDImage = append(keyIDImage, t...)
	keyIDImage = append(keyIDImage, []byte(":"+pk.Usage+":")...)
	keyIDImage = append(keyIDImage, pk.Signer[:]...)
	return sha256.Sum256(keyIDImage)
}

// GenKey generates a new key structure
func (kg KeyGenerator) GenKey() (*KeyPair, error) {
	if kg.PrivateKey == nil {
		return nil, ErrNoSigner
	}
	privateKey, publicKey, err := kg.Curve.GenerateKey()
	if err != nil {
		return nil, err
	}
	k := &KeyPair{
		PrivateKey: privateKey,
		PublicKey: PublicKey{
			PublicKey: *publicKey,
			Expire:    times.Now() + kg.ExpireTime,
			Usage:     kg.Usage,
			Signer:    *kg.PublicKey,
		},
	}
	// Create signature
	k.PublicKey.KeyID = k.PublicKey.CalcKeyID()
	sig := ed25519.Sign(kg.PrivateKey, k.PublicKey.KeyID[:])
	k.PublicKey.Signature = *sig
	return k, nil
}
