// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package length

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/uid"
)

func TestKeyEntryECDHE25519(t *testing.T) {
	var ke uid.KeyEntry
	if err := ke.InitDHKey(cipher.RandReader); err != nil {
		t.Fatal(err)
	}
	jsn, err := json.Marshal(ke)
	if err != nil {
		t.Fatal(err)
	}
	if len(jsn) != KeyEntryECDHE25519 {
		t.Error("len(jsn) != KeyEntryECDHE25519")
	}
}

func TestNil(t *testing.T) {
	jsn, err := json.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jsn) != Nil {
		t.Error("len(jsn) != Nil")
	}
}

func TestUIDMessage(t *testing.T) {
	id := strings.Repeat("lp", 32) + "@" + strings.Repeat("x", 185) + ".one"
	uid, err := uid.Create(id, true, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	uid, err = uid.Update(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// in JSON integers have a variable width, set them to maximum value
	uid.UIDContent.MSGCOUNT = 18446744073709551615
	uid.UIDContent.NOTAFTER = 18446744073709551615
	uid.UIDContent.NOTBEFORE = 18446744073709551615
	if len(uid.JSON()) != MaxUIDMessage {
		t.Error("len(uid.JSON()) != MaxUIDMessage")
	}
}
