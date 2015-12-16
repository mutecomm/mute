// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package session defines session states and session stores in Mute.
package session

import (
	"github.com/mutecomm/mute/uid"
)

// State describes the current session state between two communicating parties.
type State struct {
	SenderSessionCount          uint64        // total number of messages sent in sessions before this SenderSessionPub was used
	SenderMessageCount          uint64        // total number of messages sent with this SenderSessionPub
	RecipientSessionCount       uint64        // total number of messages received in sessions before this SenderSessionPub was used
	RecipientMessageCount       uint64        // total number of messages received with this SenderSessionPub
	RecipientTempHash           string        // RecipientKeyInitPub or RecipientSessionPub
	SenderSessionPub            uid.KeyEntry  // public session key from sender
	NextSenderSessionPub        *uid.KeyEntry // new SenderSessionPub to refresh the session
	NextRecipientSessionPubSeen *uid.KeyEntry // currently known NextSenderSessionPub of the other party
}

// The Store interface defines all methods for managing session keys.
type Store interface {
	// GetSessionState returns the current session state or nil, if no state
	// exists between the two parties.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	GetSessionState(myID, contactID string) (*State, error)
	// SetSesssionState sets the current session state between two parties.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	SetSessionState(myID, contactID string, sessionState *State) error
	// StoreSession stores a new session.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	// senderSesssionPubHash is the hash of the SenderSessionPub key.
	// rootKeyHash is the base64 encoded root key hash.
	// chainKey is the base64 encoded chain key.
	// send and recv are arrays containing NumOfFutureKeys many base64 encoded
	// future keys.
	StoreSession(myID, contactID, senderSessionPubHash, rootKeyHash,
		chainKey string, send, recv []string) error
	// HasSession returns a boolean reporting whether a session between myID
	// and contactID with senderSessionPubHash exists.
	HasSession(myID, contactID, senderSessionPubHash string) bool
	// GetPublicKeyInit returns the private KeyEntry contained in the KeyInit
	// message with the given pubKeyHash.
	GetPrivateKeyEntry(pubKeyHash string) (*uid.KeyEntry, error)
	// GetPrivateKeyInit returns a public KeyEntry and NYMADDRESS contained in
	// the KeyInit message for the given uidMsg.
	// If no such KeyEntry is available, ErrNoKeyInit is returned.
	GetPublicKeyEntry(uidMsg *uid.Message) (*uid.KeyEntry, string, error)
	// GetMessageKey returns the message key with index msgIndex. If sender is
	// true the sender key is returned, otherwise the recipient key.
	// senderSesssionPubHash is the hash of the SenderSessionPub key.
	GetMessageKey(myID, contactID, senderSessionPubHash string, sender bool,
		msgIndex uint64) (*[64]byte, error)
	// NumMessageKeys returns the number of precomputed messages keys between
	// myID and contact ID with senderSessionPubHash.
	NumMessageKeys(myID, contactID, senderSessionPubHash string) (uint64, error)
	// GetRootKeyHash returns the root key hash for the session between myID
	// and contactID with senderSessionPubHash.
	GetRootKeyHash(myID, contactID, senderSessionPubHash string) (*[64]byte,
		error)
	// GetChainKey returns the chain key for the session between myID and
	// contactID with senderSessionPubHash.
	GetChainKey(myID, contactID, senderSessionPubHash string) (*[64]byte, error)
	// DelMessageKey deleted the message key with index msgIndex. If sender is
	// true the sender key is deleted, otherwise the recipient key.
	DelMessageKey(myID, contactID, senderSessionPubHash string, sender bool,
		msgIndex uint64) error
}
