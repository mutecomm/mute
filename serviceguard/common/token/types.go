// Package token implements token type and handling functions
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/mutecomm/mute/serviceguard/common/signkeys"

	"github.com/agl/ed25519"
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/jjm"
)

const (
	// KeyIDSize is the length of the KeyID
	KeyIDSize = 32
	// NonceSize is the size of the nonce
	NonceSize = 16
	// OwnerSize is the length of the Owner key
	OwnerSize = ed25519.PublicKeySize
)

// Rand is the random number source
var Rand = rand.Reader

// Token without signature
type Token struct {
	KeyID []byte // The ID of the KeyID, 32 byte
	Flag  bool   // Flag. 0x01 == verify signature
	Nonce []byte // Random nonce
	Owner []byte // Key for owner verification

	PointRX []byte // PointR, X coordinate
	PointRY []byte // PointR, Y coordinate
	ScalarS []byte // S Scalar
	ScalarR []byte // R Scalar
}

// New creates a new Token
func New(KeyID *[signkeys.KeyIDSize]byte, Owner *[ed25519.PublicKeySize]byte) *Token {
	t := &Token{
		KeyID: make([]byte, KeyIDSize),
		Nonce: make([]byte, NonceSize),
		Owner: make([]byte, OwnerSize),
	}
	copy(t.KeyID, KeyID[:])
	if Owner == nil {
		_, err := io.ReadFull(Rand, t.Owner)
		if err != nil {
			return nil
		}
		t.Flag = false
	} else {
		copy(t.Owner, Owner[:])
		t.Flag = true
	}
	_, err := io.ReadFull(Rand, t.Nonce)
	if err != nil {
		return nil
	}
	return t
}

// Hash returns the hash of the token
func (t Token) Hash() []byte {
	h := sha256.New()
	h.Write(t.KeyID)
	if t.Flag {
		h.Write([]byte{0x01})
	} else {
		h.Write([]byte{0x00})
	}
	h.Write(t.Nonce)
	h.Write(t.Owner)
	return h.Sum(nil)
}

// Properties returns the owner and keyID of a token
func (t Token) Properties() (keyid *[signkeys.KeyIDSize]byte, owner *[ed25519.PublicKeySize]byte) {
	keyid = new([signkeys.KeyIDSize]byte)
	if t.Flag == false { // Owner is all zeros, hence, no owner
		owner = nil
	} else {
		owner = new([ed25519.PublicKeySize]byte)
		copy(owner[:], t.Owner)
	}
	copy(keyid[:], t.KeyID)
	return
}

// HasOwner returns true if the Token is owned
func (t Token) HasOwner() bool {
	return t.Flag
}

// Marshal a token
func (t Token) Marshal() ([]byte, error) {
	return asn1.Marshal(t)
}

// Unmarshal an encoded token
func Unmarshal(d []byte) (*Token, error) {
	t := new(Token)
	_, err := asn1.Unmarshal(d, t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// AddSignature adds the signature to the token
func (t *Token) AddSignature(signature *jjm.ClearSignature) {
	t.PointRX = signature.PointR.X.Bytes()
	t.PointRY = signature.PointR.Y.Bytes()
	t.ScalarR = signature.ScalarR.Bytes()
	t.ScalarS = signature.ScalarS.Bytes()
}

// GetSignature returns the signature that is part of the token
func (t *Token) GetSignature() *jjm.ClearSignature {
	ret := new(jjm.ClearSignature)
	ret.PointR = *eccutil.NewPoint(new(big.Int).SetBytes(t.PointRX), new(big.Int).SetBytes(t.PointRY))
	ret.ScalarR = new(big.Int).SetBytes(t.ScalarR)
	ret.ScalarS = new(big.Int).SetBytes(t.ScalarS)
	return ret
}
