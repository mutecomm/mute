// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"bytes"
	"io"
	"os"
	"testing"

	"crypto/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/util/times"
)

func TestAccount(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	// add acounts
	_, privkey1, err := ed25519.GenerateKey(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	_, privkey2, err := ed25519.GenerateKey(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	server1 := "accounts001.mute.berlin"
	server2 := "accounts002.mute.berlin"
	var secret1 [64]byte
	var secret2 [64]byte
	if _, err := io.ReadFull(cipher.RandReader, secret1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(cipher.RandReader, secret2[:]); err != nil {
		t.Fatal(err)
	}
	err = msgDB.AddAccount(a, "", privkey1, server1, &secret1,
		def.MinMinDelay, def.MinMaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	contacts, err := msgDB.GetAccounts(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	} else {
		if contacts[0] != "" {
			t.Error("contacts[0] != \"\"")
		}
	}
	err = msgDB.AddAccount(a, b, privkey2, server2, &secret2,
		def.MinMinDelay, def.MinMaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	// set account time
	now := times.Now()
	d90 := times.NinetyDaysLater()
	d365 := times.OneYearLater()
	if err := msgDB.SetAccountTime(a, "", d90); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.SetAccountTime(a, b, d365); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.SetAccountLastMsg(a, b, now); err != nil {
		t.Fatal(err)
	}
	// get account
	pk1, srv1, scrt1, minDelay, maxDelay, lastTime1, err := msgDB.GetAccount(a, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk1[:], privkey1[:]) {
		t.Error("pk1 != privkey1")
	}
	if srv1 != server1 {
		t.Error("srv1 != server1")
	}
	if !bytes.Equal(scrt1[:], secret1[:]) {
		t.Error("scrt1 != secret1")
	}
	if minDelay != def.MinMinDelay {
		t.Error("minDelay != def.MinMinDelay")
	}
	if maxDelay != def.MinMaxDelay {
		t.Error("maxDelay != def.MinMaxDelay")
	}
	if lastTime1 != 0 {
		t.Error("lastTime1 != 0")
	}
	pk2, srv2, scrt2, _, _, lastTime2, err := msgDB.GetAccount(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk2[:], privkey2[:]) {
		t.Error("pk2 != privkey2")
	}
	if srv2 != server2 {
		t.Error("srv2 != server2")
	}
	if !bytes.Equal(scrt2[:], secret2[:]) {
		t.Error("scrt2 != secret2")
	}
	if lastTime2 != now {
		t.Error("lastTime2 != now")
	}
	// get accounts
	contacts, err = msgDB.GetAccounts(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 {
		t.Error("len(contacts) != 2")
	} else {
		if contacts[0] != "" {
			t.Error("contacts[0] != \"\"")
		}
		if contacts[1] != b {
			t.Error("contacts[1] != b")
		}
	}
	// get account time
	t1, err := msgDB.GetAccountTime(a, "")
	if err != nil {
		t.Fatal(err)
	}
	if t1 != d90 {
		t.Error("t1 != d90")
	}
	t2, err := msgDB.GetAccountTime(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if t2 != d365 {
		t.Error("t2 != d365")
	}
}
