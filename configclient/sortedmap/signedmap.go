// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sortedmap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/mutecomm/mute/util/times"
)

var (
	// ErrNoVerify is returned when a signature could not be verified.
	ErrNoVerify = errors.New("sortedmap: signature verification failed")
	// ErrBadTime is returned if a signature time is either too old or too young.
	ErrBadTime = errors.New("sortedmap: signature time wrong")
	// ErrWalkBack is returned if an old certificate was presented.
	ErrWalkBack = errors.New("sortedmap: expired certificate replayed")
)

// MaxSignatureAge is the maximum difference between now and the signature time.
const MaxSignatureAge = 14400 // four hours

// SignedMap is a signed map.
type SignedMap struct {
	Config    StringMap
	Signature []byte
	SignDate  uint64
}

func diff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// Marshal a signed map.
func (sm *SignedMap) Marshal() ([]byte, error) {
	d, err := json.Marshal(sm)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Unmarshal a signed map back to struct.
func Unmarshal(d []byte) (*SignedMap, error) {
	sm := new(SignedMap)
	err := json.Unmarshal(d, sm)
	if err != nil {
		return nil, err
	}
	return sm, nil
}

// GenerateCertificate returns a signed and encoded SortedMap.
func (sm StringMap) GenerateCertificate(privKey *[ed25519.PrivateKeySize]byte) ([]byte, error) {
	so := sm.Sort()
	sigmap := new(SignedMap)
	sigmap.SignDate = uint64(times.Now())
	sigmap.Signature = so.Sign(sigmap.SignDate, privKey)
	sigmap.Config = sm
	return sigmap.Marshal()
}

// Certify verifies an encoded certificate.
func Certify(lastSignDate uint64, publicKey []byte, cert []byte) (*SignedMap, error) {
	sm, err := Unmarshal(cert)
	if err != nil {
		return nil, err
	}
	if lastSignDate > 0 && sm.SignDate < lastSignDate {
		return nil, ErrWalkBack
	}
	if diff(uint64(times.Now()), sm.SignDate) > MaxSignatureAge {
		return nil, ErrBadTime
	}
	if !sm.Config.Sort().Verify(sm.SignDate, publicKey, sm.Signature) {
		return nil, ErrNoVerify
	}
	return sm, nil
}
