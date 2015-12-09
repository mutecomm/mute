// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package msg defines messages in Mute. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/messages.md
package msg

import (
	"github.com/mutecomm/mute/uid"
)

// Version is the current version number of Mute messages.
const Version = 1

// DefaultCiphersuite is the default ciphersuite used for Mute messages.
const DefaultCiphersuite = "CURVE25519 XSALSA20 POLY1305"

// NumOfFutureKeys defines the default number of future message keys which
// are precomputed.
const NumOfFutureKeys = 50

// EncodedMsgSize is the size of a base64 encoded encrypted message.
const EncodedMsgSize = 65536 // 64KB

// UnencodedMsgSize is the size of unencoded encrypted message.
const UnencodedMsgSize = EncodedMsgSize / 4 * 3 // 49152

// MaxContentLength is the maximum length the content of a message can have.
const MaxContentLength = UnencodedMsgSize - preHeaderSize - encryptedHeaderSize -
	cryptoSetupSize - encryptedPacketSize - signatureSize - innerHeaderSize -
	hmacSize // 41691

// SessionState describes the current session state between communicating two
// parties.
type SessionState struct {
	SenderSessionCount    uint64 // total number of messages sent in sessions before this SenderSessionPub was used
	SenderMessageCount    uint64 // total number of messages sent with this SenderSessionPub
	RecipientSessionCount uint64 // total number of messages received in sessions before this SenderSessionPub was used
	RecipientMessageCount uint64 // total number of messages received with this SenderSessionPub
}

// The KeyStore interface defines all methods for managing session keys.
type KeyStore interface {
	// GetSessionState returns the current session state or nil, if no state
	// exists between the two parties.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	GetSessionState(myID, contactID string) (*SessionState, error)
	// SetSesssionState sets the current session state between two parties.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	SetSessionState(myID, contactID string, sessionState *SessionState) error
	// StoreSession stores a new session.
	// myID is the myID on the local side of the communication.
	// contactID is the myID on the remote side of the communication.
	// rootKeyHash is the base64 encoded root key hash.
	// chainKey is the base64 encoded chain key.
	// send and recv are arrays containing NumOfFutureKeys many base64 encoded
	// future keys.
	StoreSession(myID, contactID, rootKeyHash, chainKey string,
		send, recv []string) error
	// FindKeyEntry defines the type for a function which should return a KeyEntry
	// for the given pubKeyHash.
	FindKeyEntry(pubKeyHash string) (*uid.KeyEntry, error)
	// GetMessageKey returns the message key with index msgIndex. If sender is
	// true the sender key is returned, otherwise the recipient key.
	GetMessageKey(myID, contactID string, sender bool,
		msgIndex uint64) (*[64]byte, error)
	// DelMessageKey deleted the message key with index msgIndex. If sender is
	// true the sender key is deleted, otherwise the recipient key.
	DelMessageKey(myID, contactID string, sender bool, msgIndex uint64) error
}
