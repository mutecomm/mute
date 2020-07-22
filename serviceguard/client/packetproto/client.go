// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package packetproto implements a client of an issuer.
package packetproto

import (
	"crypto/elliptic"
	"crypto/rand"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/keypool/keydb"
	"github.com/mutecomm/mute/serviceguard/common/keypool/keydir"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/serviceguard/common/types"
	"github.com/ronperry/cryptoedge/eccutil"
)

// HashFunc of the generator. Don't mix algos!
var HashFunc = eccutil.Sha1Hash

// Curve is the elliptic curve used by the generator for blind signature keys. Do NOT mix algorithms.
var Curve = elliptic.P256

// Rand is the random source to use. System rand is the default
var Rand = rand.Reader

// Client implements a token Client
type Client struct {
	Keypool   *keypool.KeyPool             // The keypool
	PublicKey *[ed25519.PublicKeySize]byte // Public key of signer
	Curve     *eccutil.Curve
}

// New returns a new protocol client
func New(keyBackends []types.Backend) (*Client, error) {
	var err error
	c := new(Client)
	c.Curve = eccutil.SetCurve(Curve, Rand, HashFunc)
	c.Keypool = keypool.New(signkeys.New(Curve, Rand, HashFunc))
	for _, v := range keyBackends {
		if v.Type == "keydir" {
			err = keydir.Add(c.Keypool, v.Value.(string))
		} else if v.Type == "database" {
			err = keydb.Add(c.Keypool, v.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

// AddVerifyKey adds a verification key from service-guards
func (c Client) AddVerifyKey(publicKey *[ed25519.PublicKeySize]byte) {
	c.Keypool.AddVerifyKey(publicKey)
}
