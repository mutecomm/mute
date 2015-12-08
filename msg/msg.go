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

const (
	encodedMsgSize   = 65536                  // 64KB
	unencodedMsgSize = encodedMsgSize / 4 * 3 // 49152
)

// MaxContentLength is the maximum length the content of a message can have.
const MaxContentLength = unencodedMsgSize - preHeaderSize - encryptedHeaderSize -
	cryptoSetupSize - encryptedPacketSize - signatureSize - innerHeaderSize -
	hmacSize // 41691

// The KeyStore interface defines all methods for managing session keys.
type KeyStore interface {
	// StoreSession stores a new session.
	// identity is the identity on the local side of the communication.
	// partner is the identity on the remote side of the communication.
	// rootKeyHash is the base64 encoded root key hash.
	// chainKey is the base64 encoded chain key.
	// send and recv are arrays containing NumOfFutureKeys many base64 encoded
	// future keys.
	StoreSession(identity, partner, rootKeyHash, chainKey string,
		send, recv []string) error
	// FindKeyEntry defines the type for a function which should return a KeyEntry
	// for the given pubKeyHash.
	FindKeyEntry(pubKeyHash string) (*uid.KeyEntry, error)
}
