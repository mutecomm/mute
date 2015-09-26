// Package hashchain implements the hash chain for the key server in Mute.
package hashchain

import (
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// Type denotes the current hash chain type.
var Type = []byte{0x02}

// SplitEntry splits a key hashchain entry. Specification:
// https://github.com/mutecomm/mute/blob/master/doc/keyserver.md#key-hashchain-operation
func SplitEntry(entry string) (hash, typ, nonce, hashID, crUID, uidIndex []byte, err error) {
	e, err := base64.Decode(entry)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	if len(e) != 153 {
		return nil, nil, nil, nil, nil, nil, log.Errorf("entry '%s' does not have byte length 153 (but %d)", entry, len(e))
	}
	return e[:32], e[32:33], e[33:41], e[41:73], e[73:121], e[121:], nil
}
