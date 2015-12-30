// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"io"
	"os"
	"testing"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/util/times"
)

func TestNyms(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	// normal add/get cycle
	mappedID := "iohn.doe@mute.berlin"
	unmappedID := "john.doe@mute.berlin"
	fullName := "John Doe"
	if err := msgDB.AddNym(mappedID, unmappedID, fullName); err != nil {
		t.Fatal(err)
	}
	uID, fn, err := msgDB.GetNym(mappedID)
	if err != nil {
		t.Fatal(err)
	}
	if uID != unmappedID {
		t.Error("retrieved unmapped ID is wrong")
	}
	if fn != fullName {
		t.Error("retrieved full name is wrong")
	}
	// get nyms
	nyms, err := msgDB.GetNyms(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(nyms) != 1 {
		t.Error("len(nyms) != 1")
	}
	if nyms[0] != "John Doe <john.doe@mute.berlin>" {
		t.Error("nyms[0] != \"John Doe <john.doe@mute.berlin>\"")
	}
	// update key
	fullName = "John Doe Jr."
	if err := msgDB.AddNym(mappedID, unmappedID, fullName); err != nil {
		t.Fatal(err)
	}
	uID, fn, err = msgDB.GetNym(mappedID)
	if err != nil {
		t.Fatal(err)
	}
	if uID != unmappedID {
		t.Error("retrieved unmapped ID is wrong")
	}
	if fn != fullName {
		t.Error("retrieved full name is wrong")
	}
	// add empty mappedID
	if err := msgDB.AddNym("", unmappedID, fullName); err == nil {
		t.Error("adding empty mappedID should fail")
	}
	// add empty unmappedID
	if err := msgDB.AddNym(mappedID, "", fullName); err == nil {
		t.Error("adding empty unmappedID should fail")
	}
	// add unmappedID
	if err := msgDB.AddNym(unmappedID, unmappedID, fullName); err == nil {
		t.Error("adding unmappedID should fail")
	}
	// mapped and unmapped doesn't fit together
	if err := msgDB.AddNym(mappedID, "alice@mute.berlin", fullName); err == nil {
		t.Error("adding misfits should fail")
	}
	// get empty mappedID
	if value, _, err := msgDB.GetNym(""); value != "" || err == nil {
		t.Error("getting empty mappedID should fail")
	}
	// get unmappedID
	if _, _, err := msgDB.GetNym(unmappedID); err == nil {
		t.Error("getting unmappedID should fail")
	}
	// get undefined mappedID
	unmappedID, fullName, err = msgDB.GetNym("alice@mute.berlin")
	if unmappedID != "" || fullName != "" || err != nil {
		t.Error("getting undefined key mappedID return empty unmappedID and fullName")
	}
}

func TestDeleteNym(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	p := "primary@mute.berlin"
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	e := "eve@mute.berlin"
	if err := msgDB.DeleteNym(a); err == nil {
		t.Error("should fail")
	}
	if err := msgDB.AddNym(p, p, ""); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(p, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, e, e, "Eve", BlackList); err != nil {
		t.Fatal(err)
	}
	err = msgDB.AddMessage(a, b, true, "ping", false, def.MinDelay,
		def.MaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	err = msgDB.AddMessage(a, b, false, "pong", false, def.MinDelay,
		def.MaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgDB.DeleteNym(a); err != nil {
		t.Fatal(err)
	}
	num, err := msgDB.numberOfContacts()
	if err != nil {
		t.Fatal(err)
	}
	if num != 1 {
		t.Errorf("num != 1 == %d", num)
	}
	num, err = msgDB.numberOfMessages()
	if err != nil {
		t.Fatal(err)
	}
	if num != 0 {
		t.Errorf("num != 0 == %d", num)
	}
	unmappedID, _, err := msgDB.GetNym(p)
	if err != nil {
		t.Fatal(err)
	}
	if unmappedID != p {
		t.Error("unmappedID != p")
	}
}

func TestUpkeep(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	// upkeep all
	tp, err := msgDB.GetUpkeepAll(a)
	if err != nil {
		t.Fatal(err)
	}
	if tp != 0 {
		t.Error("tp != 0")
	}
	now := times.Now()
	if err := msgDB.SetUpkeepAll(a, now); err != nil {
		t.Fatal(err)
	}
	tp, err = msgDB.GetUpkeepAll(a)
	if err != nil {
		t.Fatal(err)
	}
	if tp != now {
		t.Error("tp != now")
	}
	// upkeep accounts
	tp, err = msgDB.GetUpkeepAccounts(a)
	if err != nil {
		t.Fatal(err)
	}
	if tp != 0 {
		t.Error("tp != 0")
	}
	now++
	if err := msgDB.SetUpkeepAccounts(a, now); err != nil {
		t.Fatal(err)
	}
	tp, err = msgDB.GetUpkeepAccounts(a)
	if err != nil {
		t.Fatal(err)
	}
	if tp != now {
		t.Error("tp != now")
	}
}

func TestNymUpdate(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	if err := msgDB.AddNym(a, a, ""); err != nil {
		t.Fatal(err)
	}
	var uid int64
	if err := msgDB.getNymUIDQuery.QueryRow(a).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if uid != 1 {
		t.Error("uid != 1")
	}
	_, privkey, err := ed25519.GenerateKey(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	server := "accounts001.mute.berlin"
	var secret [64]byte
	if _, err := io.ReadFull(cipher.RandReader, secret[:]); err != nil {
		t.Fatal(err)
	}
	err = msgDB.AddAccount(a, "", privkey, server, &secret,
		def.MinMinDelay, def.MinMaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgDB.getNymUIDQuery.QueryRow(a).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if uid != 1 {
		t.Error("uid != 1")
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
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	nyms, err := msgDB.GetNyms(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(nyms) != 1 {
		t.Error("len(nyms) != 1")
	} else {
		if nyms[0] != "Alice <alice@mute.berlin>" {
			t.Error("contacts[0] != \"Alice <alice@mute.berlin>\"")
		}
	}
	contacts, err = msgDB.GetAccounts(a)
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
}
