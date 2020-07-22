// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"crypto/rand"
	"testing"

	"crypto/ed25519"
)

func TestSplitKey(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	pubkey2, privkey2 := splitKey(privkey)
	if *pubkey != *pubkey2 {
		t.Error("Split: Public key wrong")
	}
	if *privkey != *privkey2 {
		t.Error("Split: Private key wrong")
	}
}

func TestLookupError(t *testing.T) {
	translated, _, err := lookupError(ErrWalletServer)
	if err != ErrWalletServer || translated == false {
		t.Error("Translation failed")
	}
}
