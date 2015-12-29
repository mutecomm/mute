// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/times"
)

func createDB() (tmpdir string, keyDB *KeyDB, err error) {
	tmpdir, err = ioutil.TempDir("", "keydb_test")
	if err != nil {
		return "", nil, err
	}
	dbname := filepath.Join(tmpdir, "keydb")
	passphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Create(dbname, passphrase, 64000); err != nil {
		return "", nil, err
	}
	keyDB, err = Open(dbname, passphrase)
	if err != nil {
		return "", nil, err
	}
	return
}

func TestHelper(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	version, err := keyDB.Version()
	if err != nil {
		t.Fatal(err)
	}
	if version != Version {
		t.Errorf("keyDB.version() != %s", Version)
	}
}

func TestRekey(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keydb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "keydb")
	passphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Create(dbname, passphrase, 64000); err != nil {
		t.Fatal(err)
	}
	keyDB, err := Open(dbname, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	keyDB.Close()
	newPassphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Rekey(dbname, passphrase, newPassphrase, 32000); err != nil {
		t.Fatal(err)
	}
	keyDB, err = Open(dbname, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyDB.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateUID(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	alice, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := uid.Create("bob@mute.one", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	if err := keyDB.AddPrivateUID(alice); err != nil {
		t.Fatal(err)
	}
	if err := keyDB.AddPrivateUID(bob); err != nil {
		t.Fatal(err)
	}

	identities, err := keyDB.GetPrivateIdentities()
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Error("wrong number of identities")
	}
	if !util.ContainsString(identities, "alice@mute.berlin") {
		t.Error("alice missing from identities")
	}
	if !util.ContainsString(identities, "bob@mute.one") {
		t.Error("bob missing from identities")
	}

	identities, err = keyDB.GetPrivateIdentitiesForDomain("mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Error("wrong number of identities")
	}
	if !util.ContainsString(identities, "alice@mute.berlin") {
		t.Error("alice missing from identities")
	}

	a, _, err := keyDB.GetPrivateUID("alice@mute.berlin", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := keyDB.GetPrivateUID("bob@mute.one", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.PrivateEncKey() != alice.PrivateEncKey() {
		t.Error("PrivateEncKeys differ")
	}
	if a.PrivateSigKey() != alice.PrivateSigKey() {
		t.Error("PrivateSigKeys differ")
	}
	if b.SigPubKey() != bob.SigPubKey() {
		t.Error("SigPubKeys differ")
	}

	key, err := cipher.Ed25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// encrypt
	_, _, UIDMessageEncrypted := alice.Encrypt()
	// create reply
	reply := uid.CreateReply(UIDMessageEncrypted, "", 0, key)
	if err := keyDB.AddPrivateUIDReply(alice, reply); err != nil {
		t.Fatal(err)
	}

	if err := keyDB.DelPrivateUID(alice); err != nil {
		t.Fatal(err)
	}
	_, _, err = keyDB.GetPrivateUID("alice@mute.berlin", false)
	if err == nil {
		t.Error("should fail")
	}
}

func TestPublicUID(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	a1, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyDB.AddPublicUID(a1, 10); err != nil {
		t.Fatal(err)
	}
	if err := keyDB.AddPublicUID(a2, 20); err != nil {
		t.Fatal(err)
	}
	var pos uint64
	var rA1 *uid.Message
	rA1, pos, _, err = keyDB.GetPublicUID("alice@mute.berlin", 10)
	if !bytes.Equal(rA1.JSON(), a1.JSON()) {
		t.Error("UID messages differ")
	}
	if pos != 10 {
		t.Error("a1 position should be 10")
	}
	var rA2 *uid.Message
	rA2, pos, _, err = keyDB.GetPublicUID("alice@mute.berlin", 30)
	if !bytes.Equal(rA2.JSON(), a2.JSON()) {
		t.Error("UID messages differ")
	}
	if pos != 20 {
		t.Error("a2 position should be 20")
	}
}

func TestPrivateKeyInit(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	msg, err := uid.Create("keydb@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	ki, pubKeyHash, privateKey, err := msg.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	err = keyDB.AddPrivateKeyInit(ki, pubKeyHash, msg.SigPubKey(), privateKey,
		"/63l/c3XB5yimoGKv6GS9TjuiM3PKVH/H/dlhnQixeIRsFRkWRl8fjXmKyQl5bk4N7DjkBPg/1GQVndhG+HWAg==")
	if err != nil {
		t.Fatal(err)
	}
	rKI, rSigPubKey, rPrivKey, err := keyDB.GetPrivateKeyInit(pubKeyHash)
	if !bytes.Equal(rKI.JSON(), ki.JSON()) {
		t.Error("KeyInits differ")
	}
	if rSigPubKey != msg.SigPubKey() {
		t.Error("SigPubKeys differ")
	}
	if rPrivKey != privateKey {
		t.Error("PrivKeys differ")
	}
}

func TestPublicKeyInit(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	msg, err := uid.Create("keydb@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	ki, _, _, err := msg.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyDB.AddPublicKeyInit(ki); err != nil {
		t.Fatal(err)
	}
	rKI, err := keyDB.GetPublicKeyInit(ki.SigKeyHash())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rKI.JSON(), ki.JSON()) {
		t.Error("KeyInits differ")
	}
}

var testHashchain = []string{
	"fL50mQtsX4/YSme3gheDTwDrvCYMYhn6A7C0nD101KAC9PP4h6aT9PgvWYD4kNkJI2nV8WThXG11Rd4Lc6uhVMOKDBBeP3140//ovQ0xALyZqlSB3Elfh1drb/CuFPFpxpkiZn12VgsY+da7o8TG0moycB66vBqwNsghTak87La6PY9MX7lPHfcdVSlFZPH3fJyxzh3060dK",
	"5u+0soN4VL5eozvRFDefcvmnSXgYmqSurB/UNsFf0HMCWdSBJxuuVzGefoKFXhgaae5FBE8lVOyQYc6WQnl1nXTN0MWfWixRloS0kkikyr+MlLdN9WHUWDAxHriJg+NrnpB/s9LGeCO0J+PMhd+pG8dpVW42o0WZJxHjisP+nm26ixzYOmPxe3AhhspfK8IPbIUndhLp7rJy",
	"4iUBVqUhQ4ZeB8drUjv6jQOXKg+ovqGKu9YZcXr2UbECEKedm1TmVFrVaQYDZL5XYOADFV8zXO7pjwM5bcK18l7A0eoiOw6bE15uzWJvqJJpAcBRx0cL3sSJUXWYivCgav0Yrm/+eczsgyvtBgXzD6bICo/6jb1SDc5a6uN3hM95/SnSkMoJFnfWX1AMc6V3djC0UVqXGZHa",
	"KHJl0l19O4GOBEuMlLox434VAwuvub2SG/QcLN2CYjkC8u+XLklLCiGO8NkwbXTxuaPLd20gMyPYZMPEUFREHMTFZcwxyvAlJpZZSzXxdKEwMgiQnWmSxAQXgbhLymPMh3LCeHUIV9N6R0YxmE52xdwZCuCK5V7Vh+tkqEMMiI+Bw6kvbAfWs2BitVWfPzV60mru2iuznDfB",
}

func TestHashchain(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	pos, found, err := keyDB.GetLastHashChainPos("mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("should not find hash chain entry")
	}
	for i, v := range testHashchain {
		if err := keyDB.AddHashChainEntry("mute.berlin", uint64(i), v); err != nil {
			t.Fatal(err)
		}
	}
	pos, found, err = keyDB.GetLastHashChainPos("mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("should find hash chain entry")
	}
	if pos != 3 {
		t.Error("last pos should be 3")
	}
	_, found, err = keyDB.GetLastHashChainPos("gmail.rocks")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("entry should not exist")
	}
	for i, v := range testHashchain {
		entry, err := keyDB.GetHashChainEntry("mute.berlin", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if entry != v {
			t.Errorf("hash chain entry %d differs", i)
		}
	}
	last, err := keyDB.GetLastHashChainEntry("mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if last != testHashchain[len(testHashchain)-1] {
		t.Errorf("last hash chain entry differs")
	}
	_, err = keyDB.GetLastHashChainEntry("gmail.rocks")
	if err == nil {
		t.Error("should fail")
	}
	if err := keyDB.DelHashChain("mute.berlin"); err != nil {
		t.Fatal(err)
	}
	pos, found, err = keyDB.GetLastHashChainPos("mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("should not find hash chain entry")
	}
	// deleting empty hash chain shouldn't produce an error
	if err := keyDB.DelHashChain("mute.berlin"); err != nil {
		t.Fatal(err)
	}
}
