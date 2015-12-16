// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util"
)

// GetSessionState implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetSessionState(myID, contactID string) (
	*session.State,
	error,
) {
	return nil, util.ErrNotImplemented
}

// SetSessionState implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) SetSessionState(
	myID, contactID string,
	sessionState *session.State,
) error {
	return util.ErrNotImplemented
}

// StoreSession implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) StoreSession(
	myID, contactID, senderSessionPubHash, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	// TODO: use senderSessionPubHash to store sessions!
	return ce.keyDB.AddSession(myID, contactID, rootKeyHash, chainKey, send, recv)
}

// HasSession implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) HasSession(
	myID, contactID, senderSessionPubHash string,
) bool {
	panic(util.ErrNotImplemented)
}

// GetPrivateKeyEntry implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetPrivateKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	log.Debugf("ce.FindKeyEntry: pubKeyHash=%s", pubKeyHash)
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

// GetPublicKeyEntry implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetPublicKeyEntry(uidMsg *uid.Message) (*uid.KeyEntry, string, error) {
	log.Debugf("ce.FindKeyEntry: uidMsg.Identity()=%s", uidMsg.Identity())
	// get KeyInit
	sigKeyHash, err := uidMsg.SigKeyHash()
	if err != nil {
		return nil, "", err
	}
	ki, err := ce.keyDB.GetPublicKeyInit(sigKeyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", session.ErrNoKeyInit
		}
		return nil, "", err
	}
	// decrypt SessionAnchor
	sa, err := ki.SessionAnchor(uidMsg.SigPubKey())
	if err != nil {
		return nil, "", err
	}
	// get KeyEntry message from SessionAnchor
	ke, err := sa.KeyEntry("ECDHE25519")
	if err != nil {
		return nil, "", err
	}
	return ke, sa.NymAddress(), nil
}

// GetMessageKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetMessageKey(
	myID, contactID, senderSessionPubHash string,
	sender bool,
	msgIndex uint64,
) (*[64]byte, error) {
	return nil, util.ErrNotImplemented
}

// NumMessageKeys implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) NumMessageKeys(
	myID, contactID, senderSessionPubHash string,
) (uint64, error) {
	return 0, util.ErrNotImplemented
}

// GetRootKeyHash implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetRootKeyHash(
	myID, contactID, senderSessionPubHash string,
) (*[64]byte, error) {
	return nil, util.ErrNotImplemented
}

// DelMessageKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) DelMessageKey(
	myID, contactID, senderSessionPubHash string,
	sender bool,
	msgIndex uint64,
) error {
	return util.ErrNotImplemented
}
