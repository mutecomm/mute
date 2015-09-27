// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package signkeys

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/agl/ed25519"
	"github.com/ronperry/cryptoedge/eccutil"
)

func TestKeyGen(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	gen := New(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	gen.PrivateKey = privkey
	gen.PublicKey = pubkey
	key, err := gen.GenKey()
	if err != nil {
		t.Fatalf("Key generation failed: %s", err)
	}
	if !key.PublicKey.Verify(pubkey) {
		t.Error("Verification failed")
	}
	m, err := key.PublicKey.Marshal()
	if err != nil {
		t.Fatalf("Key marshal failed: %s", err)
	}
	pk, err := new(PublicKey).Unmarshal(m)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}
	if pk.KeyID != key.PublicKey.KeyID {
		t.Error("KeyID wrong")
	}
	if pk.Expire != key.PublicKey.Expire {
		t.Error("Expire wrong")
	}
	if pk.Usage != key.PublicKey.Usage {
		t.Error("Usage wrong")
	}
	if pk.Signature != key.PublicKey.Signature {
		t.Error("Signature wrong")
	}
	if fmt.Sprintf("%d", pk.PublicKey.X) != fmt.Sprintf("%d", key.PublicKey.PublicKey.X) {
		t.Error("PublicKey.X wrong")
	}
	if fmt.Sprintf("%d", pk.PublicKey.Y) != fmt.Sprintf("%d", key.PublicKey.PublicKey.Y) {
		t.Error("PublicKey.Y wrong")
	}
}
