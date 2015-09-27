// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"fmt"
	"io"
	"os"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
)

// TODO: better selection of identities. Take NOTBEFORE and NOTAFTER into account.
// At the moment only the most current UID message is used for every identity.
func (ce *CryptEngine) getRecipientIdentities() ([]string, []*uid.KeyEntry, error) {
	var recipientIdentities []*uid.KeyEntry
	identities, err := ce.keyDB.GetPrivateIdentities()
	if err != nil {
		return nil, nil, err
	}
	for _, identity := range identities {
		log.Debugf("identity=%s", identity)
		msg, _, err := ce.keyDB.GetPrivateUID(identity, true)
		if err != nil {
			return nil, nil, err
		}
		recipientIdentities = append(recipientIdentities, msg.PubKey())
	}
	return identities, recipientIdentities, nil
}

func (ce *CryptEngine) findKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	log.Debugf("findKeyEntry: pubKeyHash=%s", pubKeyHash)
	ki, sigPubKey, privateKey, err := ce.keyDB.GetPrivateKeyInit(pubKeyHash)
	if err != nil {
		return nil, err
	}
	// decrypt KeyEntry
	ke, err := ki.KeyEntryECDHE25519(sigPubKey)
	if err != nil {
		return nil, err
	}
	// set private key
	if err := ke.SetPrivateKey(privateKey); err != nil {
		return nil, err
	}
	return ke, nil
}

func (ce *CryptEngine) decrypt(w io.Writer, r io.Reader, statusfp *os.File) error {
	// retrieve all possible recipient identities from keyDB
	identities, recipientIdentities, err := ce.getRecipientIdentities()
	if err != nil {
		return err
	}
	// TODO: implement this
	var previousRootKeyHash []byte

	// read pre-header
	r = base64.NewDecoder(r)
	version, preHeader, err := msg.ReadFirstOuterHeader(r)
	if err != nil {
		return err
	}

	// check version
	if version > msg.Version {
		return log.Errorf("cryptengine: newer message version, please update software")
	}
	if version < msg.Version {
		return log.Errorf("cryptengine: outdated message version, cannot process")
	}

	// decrypt message
	var senderID string
	var sig string
	senderID, sig, err = msg.Decrypt(w, identities, recipientIdentities,
		previousRootKeyHash, preHeader, r,
		func(pubKeyHash string) (*uid.KeyEntry, error) {
			return ce.findKeyEntry(pubKeyHash)
		},
		func(identity, partner, rootKeyhash, chainKey string, send, recv []string) error {
			return ce.keyDB.AddSession(identity, partner, rootKeyhash, chainKey, send, recv)
		})
	if err != nil {
		return err
	}
	fmt.Fprintf(statusfp, "SENDERIDENTITY:\t%s\n", senderID)
	if sig != "" {
		fmt.Fprintf(statusfp, "SIGNATURE:\t%s\n", sig)
	}
	return nil
}
