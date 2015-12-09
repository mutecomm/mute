// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package memstore implements a key store in memory (for testing purposes).
package memstore

import (
	"fmt"

	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
)

// MemStore implements the KeyStore interface in memory.
type MemStore struct {
	keyEntryMap map[string]*uid.KeyEntry
	sessions    map[string]*msg.SessionState
}

// New returns a new MemStore.
func New() *MemStore {
	return &MemStore{
		keyEntryMap: make(map[string]*uid.KeyEntry),
		sessions:    make(map[string]*msg.SessionState),
	}
}

// AddKeyEntry adds KeyEntry to memory store.
func (ms *MemStore) AddKeyEntry(ke *uid.KeyEntry) {
	ms.keyEntryMap[ke.HASH] = ke
}

// GetSessionState in memory.
func (ms *MemStore) GetSessionState(identity, partner string) (
	*msg.SessionState,
	error,
) {
	return ms.sessions[identity+"@"+partner], nil
}

// SetSessionState in memory.
func (ms *MemStore) SetSessionState(
	identity, partner string,
	sessionState *msg.SessionState,
) error {
	ms.sessions[identity+"@"+partner] = sessionState
	return nil
}

// StoreSession in memory.
func (ms *MemStore) StoreSession(
	identity, partner, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	// just discard at the moment
	return nil
}

// FindKeyEntry in memory.
func (ms *MemStore) FindKeyEntry(pubKeyHash string) (*uid.KeyEntry, error) {
	ke, ok := ms.keyEntryMap[pubKeyHash]
	if !ok {
		return nil, fmt.Errorf("memstore: could not find key entry %s", pubKeyHash)
	}
	return ke, nil
}
