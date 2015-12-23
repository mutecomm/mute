// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"os"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

func TestSessionStates(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	var (
		rt    uid.KeyEntry
		ssp   uid.KeyEntry
		nssp  uid.KeyEntry
		nrsps uid.KeyEntry
	)
	if err := rt.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	if err := ssp.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	if err := nssp.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	if err := nrsps.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	sessionStateKey1 := base64.Encode(cipher.SHA512([]byte("key1")))
	sessionStateKey2 := base64.Encode(cipher.SHA512([]byte("key2")))
	ss1 := &session.State{
		SenderSessionCount:          1,
		SenderMessageCount:          2,
		MaxRecipientCount:           3,
		RecipientTemp:               rt,
		SenderSessionPub:            ssp,
		NextSenderSessionPub:        &nssp,
		NextRecipientSessionPubSeen: &nrsps,
		NymAddress:                  "NYMADDRESS",
		KeyInitSession:              true,
	}
	ss2 := &session.State{
		RecipientTemp:    rt,
		SenderSessionPub: ssp,
		NymAddress:       "NYMADDRESS",
	}
	if err := keyDB.SetSessionState(sessionStateKey1, ss1); err != nil {
		t.Fatal(err)
	}
	if err := keyDB.SetSessionState(sessionStateKey2, ss2); err != nil {
		t.Fatal(err)
	}
	ss1db, err := keyDB.GetSessionState(sessionStateKey1)
	if err != nil {
		t.Fatal(err)
	}
	ss2db, err := keyDB.GetSessionState(sessionStateKey2)
	if err != nil {
		t.Fatal(err)
	}
	if !session.StateEqual(ss1, ss1db) {
		t.Error("ss1 and ss1db differ")
	}
	if !session.StateEqual(ss2, ss2db) {
		t.Error("ss2 and ss2db differ")
	}
	if err := keyDB.SetSessionState(sessionStateKey1, ss2); err != nil {
		t.Fatal(err)
	}
	ss1db, err = keyDB.GetSessionState(sessionStateKey1)
	if err != nil {
		t.Fatal(err)
	}
	if !session.StateEqual(ss2, ss1db) {
		t.Error("ss2 and ss1db differ")
	}
}
