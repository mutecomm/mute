// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hashchain implements the hash chain for the key server in Mute.
package hashchain

import (
	"bytes"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// TestEntry is a parseable hashchain entry for tests.
const TestEntry = "PxIx7lxwcKB3vmPLGzqm3alBCBkHbD89qRBWs7+N8yMB6QEQSe7yf4BrMISdYWeF/Ycm7tKzb6q8LZgdjtTHHAFSkuD/Q3aUITVhT19g5WKwEZ1TlMH0n7ymEEVVhW/PtEDOO/uMoEOKTTvwQp6QA2NE1GYYqhzBtQNHawFtw5NUnupGnDV+QqpJrSUoe/vkXnWZfDiY9Q1W"

// Type denotes the current hash chain type.
var Type = []byte{0x01}

// EntryBase64Len define the length of a hashchain entry in base64 form
const EntryBase64Len = 204

// EntryByteLen defines the length of a hashchain entry in byte form.
const EntryByteLen = 153

// SplitEntry splits a base64 encoded key hashchain entry. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/keyserver.md#key-hashchain-operation
func SplitEntry(entry string) (hash, typ, nonce, hashID, crUID, uidIndex []byte, err error) {
	e, err := base64.Decode(entry)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, log.Error(err)
	}
	if len(e) != EntryByteLen {
		return nil, nil, nil, nil, nil, nil,
			log.Errorf("hashchain: entry '%s' does not have byte length %d (but %d)",
				entry, EntryByteLen, len(e))
	}
	// HASH(entry[n]) | TYPE | NONCE | HashID | CrUID | UIDIndex
	hash = e[:32]
	typ = e[32:33]
	nonce = e[33:41]
	hashID = e[41:73]
	crUID = e[73:121]
	uidIndex = e[121:]
	// check type
	if !bytes.Equal(typ, Type) {
		return nil, nil, nil, nil, nil, nil,
			log.Errorf("hashchain: wrong type 0x%x (should be 0x%x)", typ, Type)
	}
	return
}
