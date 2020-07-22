// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydir

import (
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/ronperry/cryptoedge/eccutil"
)

var keydirectory string

func init() {
	keydirectory = filepath.Join(os.TempDir(), "serviceguard_test", "keydir")
	os.MkdirAll(keydirectory, 0700)
}

func TestGenerator(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	kp := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	Add(kp, keydirectory)
	kp.Generator.PrivateKey = privkey
	kp.Generator.PublicKey = pubkey
	kp.AddVerifyKey(pubkey)
	_ = pubkey
	key, _, err := kp.Current()
	if err != nil {
		t.Fatalf("Current failed: %s", err)
	}
	pkey, err := kp.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Errorf("Lookup failed: %s", err)
	}
	kp2 := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	Add(kp2, keydirectory)
	kp2.Generator.PrivateKey = privkey
	kp.Generator.PublicKey = pubkey
	kp2.AddVerifyKey(pubkey)
	err = kp2.Load()
	if err != nil {
		t.Errorf("Load failed: %s", err)
	}
	pkey2, err := kp2.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Fatalf("Loaded keys incomplete: %s", err)
	}
	if pkey2.KeyID != pkey.KeyID {
		t.Error("KeyID mismatch")
	}
	if pkey2.Usage != pkey.Usage {
		t.Error("Usage mismatch")
	}
	if pkey2.Signature != pkey.Signature {
		t.Error("Signature mismatch")
	}
}
