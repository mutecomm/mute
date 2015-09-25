package util

import (
	"encoding/hex"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/mix/nymaddr"
)

// MailboxAddress returns the mailbox address for the given pubkey and server.
func MailboxAddress(pubkey *[ed25519.PublicKeySize]byte, server string) []byte {
	return []byte(hex.EncodeToString(pubkey[:]) + "@" + server)
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
) (mixaddress, nymaddress string, err error) {
	// TODO: make mixaddress settable?
	mixAddresses, err := client.GetMixKeys("mix."+domain, def.CACert)
	if err != nil {
		return "", "", err
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
		return "", "", err
	}
	addr, err := nymaddr.ParseAddress(nymAddress)
	if err != nil {
		return "", "", err
	}
	return string(addr.MixAddress), base64.Encode(nymAddress), nil
}
