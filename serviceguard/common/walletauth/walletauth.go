// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package walletauth implements the wallet authentication scheme.
package walletauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/util/times"
)

var (
	// ErrBadToken signals that the token is invalid.
	ErrBadToken = errors.New("walletauth: bad token")
	// ErrBadSignature signals that a token signature does not verify.
	ErrBadSignature = errors.New("walletauth: bad signature")
	// ErrReplay is returned if a replay was detected in authentication.
	ErrReplay = errors.New("walletauth: replay on authentication")
)

// TokenSize is the size of a token.
const TokenSize = 144

// SkewWindow is the resolution of the logintime.
const SkewWindow = 3600

// Rand is the random source.
var Rand = rand.Reader

// AuthToken is an authentication token.
type AuthToken []byte

// CreateToken generates an authentication token.
func CreateToken(pubkey *[ed25519.PublicKeySize]byte, privkey *[ed25519.PrivateKeySize]byte, counter uint64) AuthToken {
	now := uint64(times.Now()) / SkewWindow
	token := make([]byte, TokenSize)
	copy(token[:32], pubkey[:])
	io.ReadFull(Rand, token[32:64])
	binary.BigEndian.PutUint64(token[64:72], now)
	binary.BigEndian.PutUint64(token[72:80], counter)
	sig := ed25519.Sign(privkey, token[:80])
	copy(token[80:], sig[:])
	return token
}

// CheckToken verifies a token signature and returns publickey, logintime and
// logincounter.
func (token AuthToken) CheckToken() (pubkey *[ed25519.PublicKeySize]byte, ltime, lcounter uint64, err error) {
	var sig [ed25519.SignatureSize]byte
	if len(token) != TokenSize {
		return nil, 0, 0, ErrBadToken
	}
	pubkey = new([ed25519.PublicKeySize]byte)
	copy(pubkey[:], token[:32])
	copy(sig[:], token[80:])
	ok := ed25519.Verify(pubkey, token[:80], &sig)
	if !ok {
		return nil, 0, 0, ErrBadSignature
	}
	ltime = binary.BigEndian.Uint64(token[64:72])
	lcounter = binary.BigEndian.Uint64(token[72:80])
	return pubkey, ltime, lcounter, nil
}

// Hash returns the hash of the authtoken (for callcache lookup).
func (token AuthToken) Hash() []byte {
	t := sha256.Sum256([]byte(token))
	return t[:]
}

// IsReplay checks if err is a replay error from walletauth and returns an
// update error and LastCounter.
// If err is no replay error, the original error is returned.
func IsReplay(err error) (uint64, error) {
	if err.Error()[:len("ErrReplay: ")] == "ErrReplay: " {
		counter := err.Error()[len("ErrReplay: "):]
		LastCounter, err := strconv.ParseInt(counter, 10, 64)
		if err == nil {
			return uint64(LastCounter), ErrReplay
		}
	}
	return 0, err
}
