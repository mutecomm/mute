// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"os"
	"testing"

	"github.com/mutecomm/mute/util/times"
)

func TestInQueue(t *testing.T) {
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
	now := times.Now()
	if err := msgDB.AddInQueue(a, "", now, "envelope1"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddInQueue(a, b, now, "envelope2"); err != nil {
		t.Fatal(err)
	}
	iqIdx, myID, contactID, msg1, env, err := msgDB.GetInQueue()
	if err != nil {
		t.Fatal(err)
	}
	if iqIdx != 1 {
		t.Error("iqIdx != 1")
	}
	if myID != a {
		t.Error("myID != a")
	}
	if contactID != "" {
		t.Error("contactID != \"\"")
	}
	if msg1 != "envelope1" {
		t.Error("msg1 != \"envelope1\"")
	}
	if !env {
		t.Error("!env")
	}
	if err := msgDB.SetInQueue(iqIdx, "encrypted1"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.RemoveInQueue(iqIdx, "plaintext1", b, false); err != nil {
		t.Fatal(err)
	}
	iqIdx, myID, contactID, msg2, env, err := msgDB.GetInQueue()
	if err != nil {
		t.Fatal(err)
	}
	if iqIdx != 2 {
		t.Error("iqIdx != 2")
	}
	if myID != a {
		t.Error("myID != a")
	}
	if contactID != b {
		t.Error("contactID != b")
	}
	if msg2 != "envelope2" {
		t.Error("msg1 != \"envelope2\"")
	}
	if !env {
		t.Error("!env")
	}
	if err := msgDB.SetInQueue(iqIdx, "encrypted2"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.DelInQueue(iqIdx); err != nil {
		t.Fatal(err)
	}
	_, myID, _, _, _, err = msgDB.GetInQueue()
	if err != nil {
		t.Fatal(err)
	}
	if myID != "" {
		t.Error("myID should be nil")
	}
}
