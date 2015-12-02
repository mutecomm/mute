// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package length

import (
	"encoding/json"
	"testing"

	"github.com/mutecomm/mute/cipher"
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
