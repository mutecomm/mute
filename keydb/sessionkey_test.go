// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"
	"os"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/times"
)

func TestSessionKeys(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	var (
		ke1 uid.KeyEntry
		ke2 uid.KeyEntry
	)
	if err := ke1.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	if err := ke2.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	ct := uint64(times.Now()) + msg.CleanupTime

	jsn1 := string(ke1.JSON())
	pk1 := ke1.PrivateKey()
	if err := keyDB.AddSessionKey(ke1.HASH, jsn1, pk1, ct); err != nil {
		t.Fatal(err)
	}

	jsn2 := string(ke2.JSON())
	pk2 := ke2.PrivateKey()
	if err := keyDB.AddSessionKey(ke2.HASH, jsn2, pk2, ct); err != nil {
		t.Fatal(err)
	}

	jsn1db, pk1db, err := keyDB.GetSessionKey(ke1.HASH)
	if err != nil {
		t.Fatal(err)
	}
	if jsn1 != jsn1db {
		t.Error("jsn1 and jsn1db differ")
	}
	if pk1 != pk1db {
		t.Error("pk1 and pk1db differ")
	}

	jsn2db, pk2db, err := keyDB.GetSessionKey(ke2.HASH)
	if err != nil {
		t.Fatal(err)
	}
	if jsn2 != jsn2db {
		t.Error("jsn2 and jsn2db differ")
	}
	if pk2 != pk2db {
		t.Error("pk2 and pk2db differ")
	}

	// getting undefined key should return sql.ErrNoRows
	_, _, err = keyDB.GetSessionKey("undefined")
	if err != sql.ErrNoRows {
		t.Error("should return sql.ErrNoRows")
	}

	// deleting non-existing key should not fail
	if err := keyDB.DelPrivSessionKey("undefined"); err != nil {
		t.Error(err)
	}

	// delete private key
	if err := keyDB.DelPrivSessionKey(ke1.HASH); err != nil {
		t.Fatal(err)
	}
	_, pk, err := keyDB.GetSessionKey(ke1.HASH)
	if err != nil {
		t.Fatal(err)
	}
	if pk != "" {
		t.Error("pk should be empty")
	}

	// deleting key again should not fail
	if err := keyDB.DelPrivSessionKey(ke1.HASH); err != nil {
		t.Error(err)
	}
}
