// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
)

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
