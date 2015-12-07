// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mixcrypt

import (
	"crypto/rand"
	"errors"

	"github.com/mutecomm/mute/util/times"
)

var (
	// ExpireReceive is the expiration time for incoming header uniqueness checks
	ExpireReceive = int64(172800)
	// ForwardMinSize is the minimum size of a forward message
	ForwardMinSize = 1024
	// ForwardMaxSize is the maximum size of a forward message
	ForwardMaxSize = 65536
	// RelayMinSize is the minimum size of a relay message
	RelayMinSize = 4096
	// RelayMaxSize is the maximum size of a relay message
	RelayMaxSize = 65536
)

var (
	// ErrNoKeys is returned if not enough keys are known
	ErrNoKeys = errors.New("mixcrypt: Keys missing")
	// ErrTooShort is returned if a message is too short
	ErrTooShort = errors.New("mixcrypt: Too short")
	// ErrSize is returned if a message is too long/short
	ErrSize = errors.New("mixcrypt: Message out of bounds")
	// ErrBadSystem is returned if a message for a wrong system was received
	ErrBadSystem = errors.New("mixcrypt: Bad system")
)

// MuteSystemDomain is the domain of the Mute System.
var MuteSystemDomain = "mute.one"

// Rand is the random source of this package.
var Rand = rand.Reader

// time source, for debugging
var timeNow = func() int64 { return times.Now() }

// KeySize is the size of a public/private key.
const KeySize = 32

const (
	// MessageTypeForward is a message that is forwarded to another mix
	MessageTypeForward = 1 + iota
	// MessageTypeRelay is a message that is relayed to a recipient
	MessageTypeRelay
)

// KeyFunc is a function that returns a private key for a public key, or nil.
type KeyFunc func(*[KeySize]byte) *[KeySize]byte
