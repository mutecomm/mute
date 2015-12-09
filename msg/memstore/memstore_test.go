// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package memstore

import (
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/times"
)

func TestMemStore(t *testing.T) {
	ms := New()
	msg, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	ki, _, _, err := msg.KeyInit(1, now+times.Day, now-times.Day, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	ke, err := ki.KeyEntryECDHE25519(msg.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	ms.AddKeyEntry(ke)
	entry, err := ms.FindKeyEntry(ke.HASH)
	if err != nil {
		t.Error(err)
	} else if entry != ke {
		t.Error("entry != ke")
	}
	if _, err := ms.FindKeyEntry("MUTE"); err == nil {
		t.Error("should fail")
	}
	err = ms.StoreSession("alice@mute.berlin", "bob@mute.berlin", "", "", nil, nil)
	if err != nil {
		t.Error(err)
	}
}
