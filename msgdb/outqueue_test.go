// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"os"
	"testing"

	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/util/times"
)

func TestOutQueue(t *testing.T) {
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
	err = msgDB.AddMessage(a, b, true, "ping", false, def.MinDelay,
		def.MaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	msgID, peer, msg, sign, minDelay, maxDelay, err := msgDB.GetUndeliveredMessage(a)
	if err != nil {
		t.Fatal(err)
	}
	if msgID != 1 {
		t.Error("msgID != 1")
	}
	if peer != b {
		t.Error("peer != b")
	}
	if string(msg) != "ping" {
		t.Error("msg != \"ping\"")
	}
	if sign {
		t.Error("sign != false")
	}
	// add encrypted message to outqueue
	err = msgDB.AddOutQueue(a, msgID, "encrypted", "nymaddress", minDelay,
		maxDelay)
	if err != nil {
		t.Fatal(err)
	}
	// afterwards there should be no undelivered message
	_, peer, _, _, _, _, err = msgDB.GetUndeliveredMessage(a)
	if err != nil {
		t.Fatal(err)
	}
	if peer != "" {
		t.Error("peer should be empty")
	}
	// get head of outqueue
	oqIdx, enc, nymaddress, minDelay, maxDelay, envelope, err := msgDB.GetOutQueue(a)
	if err != nil {
		t.Fatal(err)
	}
	if oqIdx != 1 {
		t.Error("oqIdx != 1")
	}
	if enc != "encrypted" {
		t.Error("wrong encrypted message")
	}
	if nymaddress != "nymaddress" {
		t.Error("wrong nymaddress")
	}
	if minDelay != def.MinDelay {
		t.Error("wrong minDelay")
	}
	if maxDelay != def.MaxDelay {
		t.Error("wrong maxDelay")
	}
	if envelope {
		t.Error("should not be an envelope")
	}
	// change message in outqueue to envelope
	if err := msgDB.SetOutQueue(oqIdx, "envelope"); err != nil {
		t.Fatal(err)
	}
	// get head of outqueue
	oqIdx, env, _, _, _, envelope, err := msgDB.GetOutQueue(a)
	if err != nil {
		t.Fatal(err)
	}
	if oqIdx != 1 {
		t.Error("oqIdx != 1")
	}
	if env != "envelope" {
		t.Error("wrong envelope message")
	}
	if !envelope {
		t.Error("should be an envelope")
	}
	// remove envelope from outqueue
	now := times.Now()
	if err := msgDB.RemoveOutQueue(oqIdx, now); err != nil {
		t.Fatal(err)
	}
	// get head of outqueue
	_, env, _, _, _, _, err = msgDB.GetOutQueue(a)
	if err != nil {
		t.Fatal(err)
	}
	if env != "" {
		t.Error("envelope should be empty")
	}
}
