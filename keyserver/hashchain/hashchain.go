// Package hashchain implements the hash chain for the key server in Mute.
package hashchain

import (
	"bytes"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// Type denotes the current hash chain type.
var Type = []byte{0x01}

// SplitEntry splits a base64 encoded key hashchain entry. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/keyserver.md#key-hashchain-operation
func SplitEntry(entry string) (hash, typ, nonce, hashID, crUID, uidIndex []byte, err error) {
	e, err := base64.Decode(entry)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	if len(e) != 153 {
		return nil, nil, nil, nil, nil, nil,
			log.Errorf("hashchain: entry '%s' does not have byte length 153 (but %d)", entry, len(e))
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
