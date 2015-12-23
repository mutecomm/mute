// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package memstore implements a key store in memory (for testing purposes).
package memstore

import (
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

type memSession struct {
	rootKeyHash string
	chainKey    string
	send        []string
	recv        []string
}

type sessionKey struct {
	json        string
	privKey     string
	cleanupTime uint64
}

// MemStore implements the KeyStore interface in memory.
type MemStore struct {
	privateKeyEntryMap map[string]*uid.KeyEntry
	publicKeyEntryMap  map[string]*uid.KeyEntry
	sessionStates      map[string]*session.State
	sessions           map[string]*memSession
	sessionKeys        map[string]*sessionKey
	sessionKey         string
}

// New returns a new MemStore.
func New() *MemStore {
	return &MemStore{
		privateKeyEntryMap: make(map[string]*uid.KeyEntry),
		publicKeyEntryMap:  make(map[string]*uid.KeyEntry),
		sessionStates:      make(map[string]*session.State),
		sessions:           make(map[string]*memSession),
		sessionKeys:        make(map[string]*sessionKey),
	}
}

// SessionKey returns the most recent sessionKey in MemStore.
func (ms *MemStore) SessionKey() string {
	return ms.sessionKey
}

// AddPrivateKeyEntry adds private KeyEntry to memory store.
func (ms *MemStore) AddPrivateKeyEntry(ke *uid.KeyEntry) {
	ms.privateKeyEntryMap[ke.HASH] = ke
}

// AddPublicKeyEntry adds public KeyEntry from identity to memory store.
func (ms *MemStore) AddPublicKeyEntry(identity string, ke *uid.KeyEntry) {
	ms.publicKeyEntryMap[identity] = ke
}

// GetSessionState implemented in memory.
func (ms *MemStore) GetSessionState(sessionStateKey string) (
	*session.State,
	error,
) {
	return ms.sessionStates[sessionStateKey], nil
}

// SetSessionState implemented in memory.
func (ms *MemStore) SetSessionState(
	sessionStateKey string,
	sessionState *session.State,
) error {
	ms.sessionStates[sessionStateKey] = sessionState
	return nil
}

// StoreSession implemented in memory.
func (ms *MemStore) StoreSession(
	sessionKey, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if len(send) != len(recv) {
		return log.Error("memstore: len(send) != len(recv)")
	}
	log.Debugf("memstore.StoreSession(): %s", sessionKey)
	s, ok := ms.sessions[sessionKey]
	if !ok {
		ms.sessions[sessionKey] = &memSession{
			rootKeyHash: rootKeyHash,
			chainKey:    chainKey,
			send:        send,
			recv:        recv,
		}
		ms.sessionKey = sessionKey
	} else {
		// session already exists -> update
		// rootKeyHash stays the same!
		s.chainKey = chainKey
		s.send = append(s.send, send...)
		s.recv = append(s.recv, recv...)
	}
	return nil
}

// HasSession implemented in memory.
func (ms *MemStore) HasSession(sessionKey string) bool {
	_, ok := ms.sessions[sessionKey]
	return ok
}

// GetPrivateKeyEntry implemented in memory.
func (ms *MemStore) GetPrivateKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	ke, ok := ms.privateKeyEntryMap[pubKeyHash]
	if !ok {
		return nil, log.Error(session.ErrNoKeyEntry)
	}
	return ke, nil
}

// GetPublicKeyEntry implemented in memory.
func (ms *MemStore) GetPublicKeyEntry(uidMsg *uid.Message) (*uid.KeyEntry, string, error) {
	ke, ok := ms.publicKeyEntryMap[uidMsg.Identity()]
	if !ok {
		return nil, "", log.Error(session.ErrNoKeyEntry)
	}
	return ke, "undefined", nil
}

// NumMessageKeys implemented in memory.
func (ms *MemStore) NumMessageKeys(sessionKey string) (uint64, error) {
	s, ok := ms.sessions[sessionKey]
	if !ok {
		return 0, log.Errorf("memstore: no session found for %s", sessionKey)
	}
	return uint64(len(s.send)), nil
}

// GetMessageKey implemented in memory.
func (ms *MemStore) GetMessageKey(
	sessionKey string,
	sender bool,
	msgIndex uint64,
) (*[64]byte, error) {
	s, ok := ms.sessions[sessionKey]
	if !ok {
		return nil, log.Errorf("memstore: no session found for %s", sessionKey)
	}
	if msgIndex >= uint64(len(s.send)) {
		return nil, log.Error("memstore: message index out of bounds")
	}
	var key string
	var party string
	if sender {
		key = s.send[msgIndex]
		party = "sender"
	} else {
		key = s.recv[msgIndex]
		party = "recipient"
	}
	// make sure key wasn't used yet
	if key == "" {
		return nil, log.Error(session.ErrMessageKeyUsed)
	}
	// decode key
	var messageKey [64]byte
	k, err := base64.Decode(key)
	if err != nil {
		return nil,
			log.Errorf("memstore: cannot decode %s key for %s", party,
				sessionKey)
	}
	if copy(messageKey[:], k) != 64 {
		return nil,
			log.Errorf("memstore: %s key for %s has wrong length", party,
				sessionKey)
	}
	return &messageKey, nil
}

// GetRootKeyHash implemented in memory.
func (ms *MemStore) GetRootKeyHash(sessionKey string) (*[64]byte, error) {
	s, ok := ms.sessions[sessionKey]
	if !ok {
		return nil, log.Errorf("memstore: no session found for %s", sessionKey)
	}
	// decode root key hash
	var hash [64]byte
	k, err := base64.Decode(s.rootKeyHash)
	if err != nil {
		return nil, log.Error("memstore: cannot decode root key hash")
	}
	if copy(hash[:], k) != 64 {
		return nil, log.Errorf("memstore: root key hash has wrong length")
	}
	return &hash, nil
}

// GetChainKey implemented in memory.
func (ms *MemStore) GetChainKey(sessionKey string) (*[32]byte, error) {
	s, ok := ms.sessions[sessionKey]
	if !ok {
		return nil, log.Errorf("memstore: no session found for %s", sessionKey)
	}
	// decode chain key
	var key [32]byte
	k, err := base64.Decode(s.chainKey)
	if err != nil {
		return nil, log.Error("memstore: cannot decode chain key")
	}
	if copy(key[:], k) != 32 {
		return nil, log.Errorf("memstore: chain key has wrong length")
	}
	return &key, nil
}

// DelMessageKey implemented in memory.
func (ms *MemStore) DelMessageKey(
	sessionKey string,
	sender bool,
	msgIndex uint64,
) error {
	s, ok := ms.sessions[sessionKey]
	if !ok {
		return log.Errorf("memstore: no session found for %s", sessionKey)
	}
	if msgIndex >= uint64(len(s.send)) {
		return log.Error("memstore: message index out of bounds")
	}
	// delete key
	if sender {
		s.send[msgIndex] = ""
	} else {
		s.recv[msgIndex] = ""
	}
	return nil
}

// AddSessionKey implemented in memory.
func (ms *MemStore) AddSessionKey(
	hash, json, privKey string,
	cleanupTime uint64,
) error {
	ms.sessionKeys[hash] = &sessionKey{
		json:        json,
		privKey:     privKey,
		cleanupTime: cleanupTime,
	}
	return nil
}

// GetSessionKey implemented in memory.
func (ms *MemStore) GetSessionKey(hash string) (
	json, privKey string,
	err error,
) {
	sk, ok := ms.sessionKeys[hash]
	if !ok {
		return "", "", log.Error(session.ErrNoKeyEntry)
	}
	return sk.json, sk.privKey, nil
}

// DelSessionKey implemented in memory.
func (ms *MemStore) DelSessionKey(hash string) error {
	delete(ms.sessionKeys, hash)
	return nil
}

// CleanupSessionKeys implemented in memory.
func (ms *MemStore) CleanupSessionKeys(t uint64) error {
	var oldKeys []string
	for hash, sk := range ms.sessionKeys {
		if sk.cleanupTime < t {
			oldKeys = append(oldKeys, hash)
		}
	}
	for _, hash := range oldKeys {
		delete(ms.sessionKeys, hash)
	}
	return nil
}
