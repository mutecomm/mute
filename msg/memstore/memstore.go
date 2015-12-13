// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package memstore implements a key store in memory (for testing purposes).
package memstore

import (
	"fmt"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
)

type session struct {
	rootKeyHash string
	chainKey    string
	send        []string
	recv        []string
}

// MemStore implements the KeyStore interface in memory.
type MemStore struct {
	privateKeyEntryMap map[string]*uid.KeyEntry
	publicKeyEntryMap  map[string]*uid.KeyEntry
	sessionStates      map[string]*msg.SessionState
	sessions           map[string]*session
}

// New returns a new MemStore.
func New() *MemStore {
	return &MemStore{
		privateKeyEntryMap: make(map[string]*uid.KeyEntry),
		publicKeyEntryMap:  make(map[string]*uid.KeyEntry),
		sessionStates:      make(map[string]*msg.SessionState),
		sessions:           make(map[string]*session),
	}
}

// AddPrivateKeyEntry adds private KeyEntry to memory store.
func (ms *MemStore) AddPrivateKeyEntry(ke *uid.KeyEntry) {
	ms.privateKeyEntryMap[ke.HASH] = ke
}

// AddPublicKeyEntry adds public KeyEntry from identity to memory store.
func (ms *MemStore) AddPublicKeyEntry(identity string, ke *uid.KeyEntry) {
	ms.publicKeyEntryMap[identity] = ke
}

// GetSessionState in memory.
func (ms *MemStore) GetSessionState(myID, contactID string) (
	*msg.SessionState,
	error,
) {
	return ms.sessionStates[myID+"@"+contactID], nil
}

// SetSessionState in memory.
func (ms *MemStore) SetSessionState(
	myID, contactID string,
	sessionState *msg.SessionState,
) error {
	ms.sessionStates[myID+"@"+contactID] = sessionState
	return nil
}

// StoreSession in memory.
func (ms *MemStore) StoreSession(
	myID, contactID, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if err := identity.IsMapped(contactID); err != nil {
		return log.Error(err)
	}
	if len(send) != len(recv) {
		return log.Error("memstore: len(send) != len(recv)")
	}
	ms.sessions[myID+"@"+contactID] = &session{
		rootKeyHash: rootKeyHash,
		chainKey:    chainKey,
		send:        send,
		recv:        recv,
	}
	return nil
}

// GetPrivateKeyEntry in memory.
func (ms *MemStore) GetPrivateKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	ke, ok := ms.privateKeyEntryMap[pubKeyHash]
	if !ok {
		return nil, fmt.Errorf("memstore: could not find key entry %s", pubKeyHash)
	}
	return ke, nil
}

// GetPublicKeyEntry in memory.
func (ms *MemStore) GetPublicKeyEntry(uidMsg *uid.Message) (*uid.KeyEntry, string, error) {
	ke, ok := ms.publicKeyEntryMap[uidMsg.Identity()]
	if !ok {
		return nil, "", msg.ErrNoKeyInit
	}
	return ke, "undefined", nil
}

// GetMessageKey in memory.
func (ms *MemStore) GetMessageKey(
	myID, contactID string,
	sender bool,
	msgIndex uint64,
) (*[64]byte, error) {
	session, ok := ms.sessions[myID+"@"+contactID]
	if !ok {
		return nil, log.Errorf("memstore: no session found for %s and %s",
			myID, contactID)
	}
	var key string
	var party string
	if sender {
		key = session.send[msgIndex] // TODO: this could panic
		party = "sender"
	} else {
		key = session.recv[msgIndex] // TODO: this could panic
		party = "recipient"
	}
	// make sure key wasn't used yet
	if key == "" {
		return nil, log.Error(msg.ErrMessageKeyUsed)
	}
	// decode key
	var messageKey [64]byte
	k, err := base64.Decode(key)
	if err != nil {
		return nil, log.Errorf("memstore: cannot decode %s key for %s and %s: ",
			party, myID, contactID)
	}
	if copy(messageKey[:], k) != 64 {
		return nil, log.Errorf("memstore: %s key for %s and %s has wrong length",
			party, myID, contactID)
	}
	return &messageKey, nil
}

// DelMessageKey in memory.
func (ms *MemStore) DelMessageKey(
	myID, contactID string,
	sender bool,
	msgIndex uint64,
) error {
	session, ok := ms.sessions[myID+"@"+contactID]
	if !ok {
		return log.Errorf("memstore: no session found for %s and %s",
			myID, contactID)
	}
	// delete key
	if sender {
		session.send[msgIndex] = "" // TODO: this could panic
	} else {
		session.recv[msgIndex] = "" // TODO: this could panic
	}
	return nil
}
