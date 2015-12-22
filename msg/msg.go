// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package msg defines messages in Mute. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/messages.md
package msg

// Version is the current version number of Mute messages.
const Version = 1

// DefaultCiphersuite is the default ciphersuite used for Mute messages.
const DefaultCiphersuite = "CURVE25519 XSALSA20 POLY1305"

// NumOfFutureKeys defines the default number of future message keys which
// are precomputed.
const NumOfFutureKeys = 50

// AverageSessionSize defines the average session size. That is, the number of
// keys used in a session before a new session is started.
// For every encrypted message there is the probability of
// 1/AverageSessionSize that it starts a new session.
const AverageSessionSize = 1000

// EncodedMsgSize is the size of a base64 encoded encrypted message.
const EncodedMsgSize = 65536 // 64KB

// UnencodedMsgSize is the size of unencoded encrypted message.
const UnencodedMsgSize = EncodedMsgSize / 4 * 3 // 49152

// MaxContentLength is the maximum length the content of a message can have.
const MaxContentLength = UnencodedMsgSize - preHeaderSize - encryptedHeaderSize -
	cryptoSetupSize - encryptedPacketSize - signatureSize - innerHeaderSize -
	hmacSize // 41691

// SendTime defines how long key material can be used for sending.
const SendTime = 172800 // 48h

// CleanupTime defines the time how long key material should be retained.
// Initialized via def.InitMute().
var CleanupTime uint64
