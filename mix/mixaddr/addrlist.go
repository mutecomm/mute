// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mixaddr implements key handling functions for mixes and mix clients.
package mixaddr

import (
	"crypto"
	_ "crypto/sha256" // import sha256
	"encoding/binary"
	"encoding/json"
	"math/rand"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/util/times"
)

var timeNow = func() int64 { return times.Now() }

// Address contains a mix address.
type Address struct {
	Pubkey   []byte // The mix public key
	Expire   int64  // Time the key expires
	Address  string // The address where the mix listens
	TokenKey []byte // The token key of that mix
}

// AddressStatement contains a statement by a mix concerning its addresses.
type AddressStatement struct {
	Addresses AddressList
	Signature []byte
	PublicKey []byte
}

// AddressList contains many addresses.
type AddressList []Address

// image the entry for hashing
func (adr Address) image() []byte {
	d := make([]byte, 8)
	binary.BigEndian.PutUint64(d, uint64(adr.Expire))
	image := make([]byte, 0, len(adr.Pubkey)+len(adr.Address)+len(adr.TokenKey)+8)
	image = append(image, adr.Pubkey...)
	image = append(image, d...)
	image = append(image, adr.Address...)
	image = append(image, adr.TokenKey...)
	return image
}

func (adl AddressList) hash() []byte {
	hasher := crypto.SHA256.New()
	for _, entry := range adl {
		hasher.Write(entry.image())
	}
	hashSum := hasher.Sum(make([]byte, 0))
	return hashSum
}

// Sign a mix address list.
func (adl AddressList) Sign(privateKey *[ed25519.PrivateKeySize]byte) []byte {
	hashSum := adl.hash()
	sig := ed25519.Sign(privateKey, hashSum)
	return sig[:]
}

// Statement for an AddressList.
func (adl AddressList) Statement(privateKey *[ed25519.PrivateKeySize]byte) AddressStatement {
	pubkey := getPubKey(privateKey)
	stmt := AddressStatement{
		Addresses: adl,
		PublicKey: pubkey[:],
		Signature: adl.Sign(privateKey),
	}
	return stmt
}

// getPubKey returns the public part of an ed25519 private key
func getPubKey(privateKey *[ed25519.PrivateKeySize]byte) *[ed25519.PublicKeySize]byte {
	r := new([ed25519.PublicKeySize]byte)
	copy(r[:], privateKey[ed25519.PrivateKeySize-ed25519.PublicKeySize:])
	return r
}

// Verify an AddressStatement.
func (stmt AddressStatement) Verify() bool {
	var pubKey [ed25519.PublicKeySize]byte
	var signature [ed25519.SignatureSize]byte
	copy(pubKey[:], stmt.PublicKey)
	copy(signature[:], stmt.Signature)
	return stmt.Addresses.Verify(&pubKey, &signature)
}

// Verify a mix address list.
func (adl AddressList) Verify(publicKey *[ed25519.PublicKeySize]byte, signature *[ed25519.SignatureSize]byte) bool {
	hashSum := adl.hash()
	return ed25519.Verify(publicKey, hashSum, signature)
}

// Expire entries from addressList. Returns new addresslist.
func (adl AddressList) Expire(now int64) AddressList {
	if now == 0 {
		now = timeNow()
	}
	nadl := make(AddressList, 0)
	for _, e := range adl {
		if e.Expire > now {
			nadl = append(nadl, e)
		}
	}
	return nadl
}

// Append an address to an addresslist.
func (adl AddressList) Append(adr ...Address) AddressList {
	now := timeNow()
	if adl == nil {
		adl = make(AddressList, 0)
	}
	for _, a := range adr {
		if a.Expire > now {
			adl = append(adl, a)
		}
	}
	return adl
}

// AddStatement adds an address statement to the list of addresses.
func (adl AddressList) AddStatement(stmt AddressStatement) AddressList {
	if adl == nil {
		adl = make(AddressList, 0)
	}
	if stmt.Verify() {
		return adl.Append(stmt.Addresses...)
	}
	return adl
}

// Rand returns a random address from the addresslist.
func (adl AddressList) Rand() *Address {
	if adl == nil || len(adl) == 0 {
		return nil
	}
	rand.Seed(times.NowNano())
	return &adl[int(rand.Int31())%len(adl)]
}

// Marshal an addresslist.
func (adl AddressList) Marshal() []byte {
	d, err := json.MarshalIndent(adl, "", "    ")
	if err != nil {
		panic(err) // should never happen
	}
	return d
}

// Unmarshal an addresslist.
func (adl AddressList) Unmarshal(d []byte) (AddressList, error) {
	al := make(AddressList, 0)
	err := json.Unmarshal(d, &al)
	return al.Expire(0), err
}
