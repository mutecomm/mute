// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/times"
	"golang.org/x/crypto/hkdf"
)

func createDB() (tmpdir string, keyDB *KeyDB, err error) {
	tmpdir, err = ioutil.TempDir("", "keydb_test")
	if err != nil {
		return "", nil, err
	}
	dbname := path.Join(tmpdir, "keydb")
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
	dbname := path.Join(tmpdir, "keydb")
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
	alice, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := uid.Create("bob@mute.one", false, "", "", uid.Strict, cipher.RandReader)
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

	if err := keyDB.DeletePrivateUID(alice); err != nil {
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
	a1, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict, cipher.RandReader)
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
	msg, err := uid.Create("keydb@mute.berlin", false, "", "", uid.Strict, cipher.RandReader)
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
	msg, err := uid.Create("keydb@mute.berlin", false, "", "", uid.Strict, cipher.RandReader)
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

func deriveKeys(chainKey []byte, kdf io.Reader) (send, recv []string, err error) {
	buffer := make([]byte, 64)
	for i := 0; i < msg.NumOfFutureKeys; i++ {
		if _, err := io.ReadFull(kdf, buffer); err != nil {
			return nil, nil, err
		}
		send = append(send, base64.Encode(cipher.HMAC(chainKey, buffer)))
		if _, err := io.ReadFull(kdf, buffer); err != nil {
			return nil, nil, err
		}
		recv = append(recv, base64.Encode(cipher.HMAC(chainKey, buffer)))
	}
	return
}

func TestSessions(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	// make sure sessions are empty initially
	rootKeyHash, err := keyDB.GetSession("alice@mute.berlin", "bob@mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyHash != "" {
		t.Fatal("rootKeyHash is supposed to be empty")
	}
	// store root key hash
	a := base64.Encode(cipher.SHA256([]byte("foo")))
	master := make([]byte, 96)
	if _, err := io.ReadFull(cipher.RandReader, master); err != nil {
		t.Fatal(err)
	}
	kdf := hkdf.New(sha512.New, master, nil, nil)
	chainKey := make([]byte, 24)
	if _, err := io.ReadFull(kdf, chainKey); err != nil {
		t.Fatal(err)
	}
	send, recv, err := deriveKeys(chainKey, kdf)
	if err != nil {
		t.Fatal(err)
	}
	err = keyDB.AddSession("alice@mute.berlin", "bob@mute.berlin", a, base64.Encode(chainKey), send, recv)
	if err != nil {
		t.Fatal(err)
	}
	// check root key hash
	rootKeyHash, err = keyDB.GetSession("alice@mute.berlin", "bob@mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyHash != a {
		t.Fatalf("rootKeyHash is supposed to equal a")
	}
	// update root key hash
	b := base64.Encode(cipher.SHA256([]byte("bar")))
	chainKey = make([]byte, 24)
	if _, err := io.ReadFull(kdf, chainKey); err != nil {
		t.Fatal(err)
	}
	send, recv, err = deriveKeys(chainKey, kdf)
	if err != nil {
		t.Fatal(err)
	}
	err = keyDB.AddSession("alice@mute.berlin", "bob@mute.berlin", b, base64.Encode(chainKey), send, recv)
	if err != nil {
		t.Fatal(err)
	}
	// check updated root key hash
	rootKeyHash, err = keyDB.GetSession("alice@mute.berlin", "bob@mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyHash != b {
		fmt.Printf("%s\n%s\n", rootKeyHash, b)
		t.Fatalf("rootKeyHash is supposed to equal b")
	}
}

var hashchain = []string{
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
	for i, v := range hashchain {
		if err := keyDB.AddHashChainEntry("mute.berlin", uint64(i), v); err != nil {
			t.Fatal(err)
		}
	}
	pos, found, err := keyDB.GetLastHashChainPos("mute.berlin")
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
	for i, v := range hashchain {
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
	if last != hashchain[len(hashchain)-1] {
		t.Errorf("last hash chain entry differs")
	}
	_, err = keyDB.GetLastHashChainEntry("gmail.rocks")
	if err == nil {
		t.Error("should fail")
	}
}
