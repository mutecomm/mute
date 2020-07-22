// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"bytes"
	"testing"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
)

func TestNew(t *testing.T) {
	keyID := [signkeys.KeyIDSize]byte{0x01, 0x03, 0x01}
	owner := [ed25519.PublicKeySize]byte{0x00, 0x15, 0xff}
	tkn := New(&keyID, nil)
	if tkn.HasOwner() {
		t.Error("Token should NOT have an owner")
	}
	hsh := tkn.Hash()
	tkn = New(&keyID, &owner)
	if !tkn.HasOwner() {
		t.Error("Token should have an owner")
	}
	keyIDr, ownerr := tkn.Properties()
	if *keyIDr != keyID {
		t.Error("KeyID mismatch")
	}
	if *ownerr != owner {
		t.Error("Owner mismatch")
	}
	hsh1 := tkn.Hash()
	m, err := tkn.Marshal()
	if err != nil {
		t.Errorf("Marshal error: %s", err)
	}
	tkn2, err := Unmarshal(m)
	if err != nil {
		t.Errorf("Unmarshal error: %s", err)
	}
	hsh2 := tkn2.Hash()
	if bytes.Equal(hsh, hsh1) {
		t.Error("hsh and hsh1 must differ")
	}
	if !bytes.Equal(hsh1, hsh2) {
		t.Error("hsh and hsh2 must match")
	}
}
