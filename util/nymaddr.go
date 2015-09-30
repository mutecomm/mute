// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"encoding/hex"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/mix/mixcrypt"
	"github.com/mutecomm/mute/mix/nymaddr"
)

// MixAddress defines the mix address.
//
// TODO: Allow multiple domains.
var MixAddress string

// MailboxAddress returns the mailbox address for the given pubkey and server.
func MailboxAddress(pubkey *[ed25519.PublicKeySize]byte, server string) []byte {
	return []byte(hex.EncodeToString(pubkey[:]) + "@" +
		server[:len(server)-len(mixcrypt.MuteSystemDomain)])
}

// NewNymAddress generates a new nym address.
func NewNymAddress(
	domain string,
	secret []byte,
	expire int64,
	singleUse bool,
	minDelay, maxDelay int32,
	identity string,
	pubkey *[ed25519.PublicKeySize]byte,
	server string,
	caCert []byte,
) (mixaddress, nymaddress string, err error) {
	if MixAddress == "" {
		return "", "", log.Error("util: MixAddress undefined")
	}
	mixAddresses, err := client.GetMixKeys(MixAddress, caCert)
	if err != nil {
		return "", "", log.Error(err)
	}
	tmp := nymaddr.AddressTemplate{
		Secret:        secret,
		System:        0,
		MixCandidates: mixAddresses.Addresses,
		Expire:        expire,
		SingleUse:     singleUse,
		MinDelay:      minDelay,
		MaxDelay:      maxDelay,
	}
	nymAddress, err := tmp.NewAddress(MailboxAddress(pubkey, server),
		cipher.SHA256([]byte(identity)))
	if err != nil {
		return "", "", log.Error(err)
	}
	addr, err := nymaddr.ParseAddress(nymAddress)
	if err != nil {
		return "", "", log.Error(err)
	}
	return string(addr.MixAddress), base64.Encode(nymAddress), nil
}
