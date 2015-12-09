// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package memstore implements a key store in memory (for testing purposes).
package memstore

import (
	"fmt"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
)

type session struct {
	rootKeyHash string
	chainKey    string
	send        []string
	recv        []string
}

// MemStore implements the KeyStore interface in memory.
type MemStore struct {
	keyEntryMap   map[string]*uid.KeyEntry
	sessionStates map[string]*msg.SessionState
	sessions      map[string]*session
}

// New returns a new MemStore.
func New() *MemStore {
	return &MemStore{
		keyEntryMap:   make(map[string]*uid.KeyEntry),
		sessionStates: make(map[string]*msg.SessionState),
		sessions:      make(map[string]*session),
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
	return ms.sessionStates[identity+"@"+partner], nil
}

// SetSessionState in memory.
func (ms *MemStore) SetSessionState(
	identity, partner string,
	sessionState *msg.SessionState,
) error {
	ms.sessionStates[identity+"@"+partner] = sessionState
	return nil
}

// StoreSession in memory.
func (ms *MemStore) StoreSession(
	identity, partner, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if len(send) != len(recv) {
		return log.Error("memstore: len(send) != len(recv)")
	}
	ms.sessions[identity+"@"+partner] = &session{
		rootKeyHash: rootKeyHash,
		chainKey:    chainKey,
		send:        send,
		recv:        recv,
	}
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
