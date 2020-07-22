// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"crypto/ed25519"
	_ "github.com/mutecomm/go-sqlcipher"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/util/times"
	"github.com/ronperry/cryptoedge/eccutil"
)

func init() {
	// Travis doesn't use a password for MySQL, but locally we do
	if os.Getenv("TRAVIS") == "true" {
		database = "root@/spendbook"
	} else {
		database = "root:root@/spendbook"
	}
}

var database string
var sqliteDB = filepath.Join(os.TempDir(), "keypoolDB-"+strconv.FormatInt(times.Now(), 10)+".db")

func TestGenerator(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	kp := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	err := Add(kp, database)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
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
	err = Add(kp2, database)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
	kp2.Generator.PrivateKey = privkey
	kp2.Generator.PublicKey = pubkey
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
	kp3 := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	kp3.Generator.PrivateKey = privkey
	kp3.Generator.PublicKey = pubkey
	kp3.AddVerifyKey(pubkey)
	err = Add(kp3, database)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
	pkey3, err := kp3.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Fatalf("Fetch does not work: %s", err)
	}
	if pkey3.KeyID != pkey.KeyID {
		t.Error("KeyID mismatch")
	}
	if pkey3.Usage != pkey.Usage {
		t.Error("Usage mismatch")
	}
	if pkey3.Signature != pkey.Signature {
		t.Error("Signature mismatch")
	}
}

func TestGeneratorSQLite3(t *testing.T) {
	dbHandle, err := sql.Open("sqlite3", sqliteDB)
	if err != nil {
		t.Fatalf("SQLiteDB Open failed: %s", err)
	}
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	kp := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	err = Add(kp, dbHandle)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
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
	err = Add(kp2, dbHandle)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
	kp2.Generator.PrivateKey = privkey
	kp2.Generator.PublicKey = pubkey
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
	kp3 := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	kp3.Generator.PrivateKey = privkey
	kp3.Generator.PublicKey = pubkey
	kp3.AddVerifyKey(pubkey)
	err = Add(kp3, dbHandle)
	if err != nil {
		t.Fatalf("Storage addition failed: %s", err)
	}
	pkey3, err := kp3.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Fatalf("Fetch does not work: %s", err)
	}
	if pkey3.KeyID != pkey.KeyID {
		t.Error("KeyID mismatch")
	}
	if pkey3.Usage != pkey.Usage {
		t.Error("Usage mismatch")
	}
	if pkey3.Signature != pkey.Signature {
		t.Error("Signature mismatch")
	}
	dbHandle.Close()
	os.Remove(sqliteDB)
}
