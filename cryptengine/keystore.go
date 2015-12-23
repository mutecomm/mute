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
func (ce *CryptEngine) GetSessionState(sessionStateKey string) (
	*session.State,
	error,
) {
	ss, err := ce.keyDB.GetSessionState(sessionStateKey)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

// SetSessionState implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) SetSessionState(
	sessionStateKey string,
	sessionState *session.State,
) error {
	return ce.keyDB.SetSessionState(sessionStateKey, sessionState)
}

// StoreSession implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) StoreSession(
	sessionKey, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	// TODO: use senderSessionPubHash to store sessions!
	// TODO: return ce.keyDB.AddSession(myID, contactID, rootKeyHash, chainKey, send, recv)
	return util.ErrNotImplemented
}

// HasSession implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) HasSession(sessionKey string) bool {
	panic(util.ErrNotImplemented)
}

// GetPrivateKeyEntry implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetPrivateKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	log.Debugf("ce.FindKeyEntry: pubKeyHash=%s", pubKeyHash)
	ki, sigPubKey, privateKey, err := ce.keyDB.GetPrivateKeyInit(pubKeyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, session.ErrNoKeyEntry
		}
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
			return nil, "", session.ErrNoKeyEntry
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
	sessionKey string,
	sender bool,
	msgIndex uint64,
) (*[64]byte, error) {
	return nil, util.ErrNotImplemented
}

// NumMessageKeys implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) NumMessageKeys(sessionKey string) (uint64, error) {
	return 0, util.ErrNotImplemented
}

// GetRootKeyHash implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetRootKeyHash(sessionKey string) (*[64]byte, error) {
	return nil, util.ErrNotImplemented
}

// GetChainKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetChainKey(sessionKey string) (*[32]byte, error) {
	return nil, util.ErrNotImplemented
}

// DelMessageKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) DelMessageKey(
	sessionKey string,
	sender bool,
	msgIndex uint64,
) error {
	return util.ErrNotImplemented
}

// AddSessionKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) AddSessionKey(
	hash, json, privKey string,
	cleanupTime uint64,
) error {
	return util.ErrNotImplemented
}

// GetSessionKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) GetSessionKey(hash string) (
	json, privKey string,
	err error,
) {
	return "", "", util.ErrNotImplemented
}

// DelPrivSessionKey implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) DelPrivSessionKey(hash string) error {
	return util.ErrNotImplemented
}

// CleanupSessionKeys implements corresponding method for msg.KeyStore interface.
func (ce *CryptEngine) CleanupSessionKeys(t uint64) error {
	return util.ErrNotImplemented
}
