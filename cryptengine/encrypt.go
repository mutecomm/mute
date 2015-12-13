// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid/identity"
)

// encrypt reads data from r, encrypts it for identity to (with identity from
// as sender), and writes it to w.
func (ce *CryptEngine) encrypt(
	w io.Writer,
	from, to string,
	sign bool,
	r io.Reader,
	statusfp *os.File,
) error {
	// map pseudonyms
	fromID, fromDomain, err := identity.MapPlus(from)
	if err != nil {
		return err
	}
	toID, err := identity.Map(to)
	if err != nil {
		return err
	}
	// get fromUID from keyDB
	fromUID, _, err := ce.keyDB.GetPrivateUID(fromID, true)
	if err != nil {
		return err
	}
	// get toUID from keyDB
	toUID, _, found, err := ce.keyDB.GetPublicUID(toID, math.MaxInt64) // TODO: use simpler API
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("not UID for '%s' found", toID)
	}
	// encrypt message
	senderLastKeychainHash, err := ce.keyDB.GetLastHashChainEntry(fromDomain)
	if err != nil {
		return err
	}
	var privateSigKey *[64]byte
	if sign {
		privateSigKey = fromUID.PrivateSigKey64()
	}
	args := &msg.EncryptArgs{
		Writer: w,
		From:   fromUID,
		To:     toUID,
		SenderLastKeychainHash: senderLastKeychainHash,
		PrivateSigKey:          privateSigKey,
		Reader:                 r,
		Rand:                   cipher.RandReader,
		KeyStore:               ce,
	}
	nymAddress, err := msg.Encrypt(args)
	if err != nil {
		return err
	}
	// show nymaddress on status-fd
	fmt.Fprintf(statusfp, "NYMADDRESS:\t%s\n", nymAddress)
	return nil
}
