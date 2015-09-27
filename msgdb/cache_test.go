// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"errors"
	"os"
	"testing"
)

func testCache(msgDB *MsgDB, myID, contactID string) error {
	if err := msgDB.AddMessageIDCache(myID, contactID, "1"); err != nil {
		return err
	}
	if err := msgDB.AddMessageIDCache(myID, contactID, "2"); err != nil {
		return err
	}
	if err := msgDB.AddMessageIDCache(myID, contactID, "3"); err != nil {
		return err
	}
	cache, err := msgDB.GetMessageIDCache(myID, contactID)
	if err != nil {
		return err
	}
	if !cache["1"] {
		return errors.New("1 not in cache")
	}
	if !cache["2"] {
		return errors.New("2 not in cache")
	}
	if !cache["3"] {
		return errors.New("3 not in cache")
	}
	if cache["4"] {
		return errors.New("4 in cache")
	}
	if err := msgDB.RemoveMessageIDCache(myID, contactID, "2"); err != nil {
		return err
	}
	cache, err = msgDB.GetMessageIDCache(myID, contactID)
	if err != nil {
		return err
	}
	if cache["1"] {
		return errors.New("1 in cache")
	}
	if !cache["2"] {
		return errors.New("2 not in cache")
	}
	if !cache["3"] {
		return errors.New("3 not in cache")
	}
	return nil
}

func TestMessageIDCache(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	if err := msgDB.AddNym(a, a, ""); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	if err := testCache(msgDB, a, ""); err != nil {
		t.Fatal(err)
	}
	if err := testCache(msgDB, a, b); err != nil {
		t.Fatal(err)
	}
}
