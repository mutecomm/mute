// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	keylookupClient "github.com/mutecomm/mute/serviceguard/client/keylookup"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/serviceguard/common/token"
	"github.com/mutecomm/mute/util/times"
	"github.com/ronperry/cryptoedge/jjm"
)

// Verify a given inputToken and return it's public key if it verifies.
func (c *Client) Verify(inputToken []byte) (outputToken *TokenEntry, err error) {
	tokenUnmarshalled, err := token.Unmarshal(inputToken)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	keyid, owner := tokenUnmarshalled.Properties()
	pubkey, err := c.getPubKey(*keyid)
	if err != nil {
		return nil, err
	}
	// Check if it is expired. Duplicate. Keypool does that as well
	if pubkey.Expire < times.Now() {
		c.LastError = ErrExpireToken
		return nil, ErrFinal
	}
	// Get data from token, signature first
	signature := tokenUnmarshalled.GetSignature()
	tempSignature := jjm.NewClearSignature(&pubkey.PublicKey)
	tempSignature.PointR = signature.PointR
	tempSignature.ScalarS = signature.ScalarS
	tempSignature.ScalarR = signature.ScalarR
	// Get signature message
	clearMessage := jjm.NewClearMessage(tokenUnmarshalled.Hash())
	// Verify the signature
	blindClient := jjm.NewGenericBlindingClient(&pubkey.PublicKey, c.packetClient.Curve)
	ok, err := blindClient.Verify(tempSignature, clearMessage)
	if err != nil || !ok {
		c.LastError = err
		return nil, ErrFinal
	}
	outputToken = &TokenEntry{
		Hash:        tokenUnmarshalled.Hash(),
		Token:       inputToken,
		OwnerPubKey: owner,
		Usage:       pubkey.Usage,
		Expire:      pubkey.Expire,
	}
	return outputToken, nil
}

// getPubKey looks up a public key from the keypool and tries to fetch it from
// keylookup if necessary.
func (c *Client) getPubKey(keyid [signkeys.KeyIDSize]byte) (pubkey *signkeys.PublicKey, err error) {
	pubkey, err = c.packetClient.Keypool.Lookup(keyid)
	if err != nil {
		if err != keypool.ErrNotFound {
			c.LastError = err
			return nil, ErrFatal
		}
		if !c.IsOnline() {
			c.LastError = err
			return nil, ErrOffline
		}
		onlineGroup.Add(1)
		defer onlineGroup.Done()
		lookupClient := keylookupClient.New(nil, c.cacert, TrustRoot)
		pubkey, err = lookupClient.GetKey(&keyid)
		if err != nil {
			_, fatal, err := lookupError(err)
			c.LastError = err
			if fatal {
				return nil, ErrFinal
			}
			return nil, ErrRetry
		}
		_, err = c.packetClient.Keypool.LoadKey(pubkey)
		if err != nil && err != keypool.ErrExists {
			c.LastError = err
			return nil, ErrFatal
		}
	}
	return pubkey, nil
}
