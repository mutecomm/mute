// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mixaddr

import (
	"crypto/rand"
	"testing"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/util/times"
)

var now = times.Now()
var ta0 = Address{
	Pubkey:  []byte("Pubkey 0"),
	Expire:  now,
	Address: "Address 0",
}
var ta1 = Address{
	Pubkey:  []byte("Pubkey 1"),
	Expire:  now + 2,
	Address: "Address 1",
}
var ta2 = Address{
	Pubkey:  []byte("Pubkey 2"),
	Expire:  now + 100,
	Address: "Address 2",
}
var ta3 = Address{
	Pubkey:  []byte("Pubkey 3"),
	Expire:  now + 100,
	Address: "Address 2",
}
var ta4 = Address{
	Pubkey:  []byte("Pubkey 4"),
	Expire:  now + 100,
	Address: "Address 2",
}

func TestAppend(t *testing.T) {
	var list AddressList

	list = list.Append(ta0, ta1, ta2)
	found := 0
	for _, e := range list {
		if string(e.Address) == string(ta2.Address) {
			found++
		}
		if string(e.Address) == string(ta1.Address) {
			found++
		}
		if string(e.Address) == string(ta0.Address) {
			found++
		}
	}
	if found > 2 {
		t.Fatal("Append did not verify expire")
	}
	if found < 2 {
		t.Fatal("Missing entries")
	}
	_, privkey, _ := ed25519.GenerateKey(rand.Reader)
	stmt := list.Statement(privkey)
	if !stmt.Verify() {
		t.Fatal("AddressList statement did not verify")
	}
	timeNow = func() int64 { return now + 2 }
	list = list.Expire(0)
	found = 0
	for _, e := range list {
		if string(e.Address) == string(ta2.Address) {
			found++
		}
		if string(e.Address) == string(ta1.Address) {
			found++
		}
		if string(e.Address) == string(ta0.Address) {
			found++
		}
	}
	if found != 1 {
		t.Fatal("Expire misrun")
	}
}

func TestMarshal(t *testing.T) {
	var list, list2 AddressList
	list = list.Append(ta2, ta3, ta4)
	marshalledList := list.Marshal()
	list2, err := list2.Unmarshal(marshalledList)
	if err != nil {
		t.Errorf("Unmarshal: %s", err)
	}
	if len(list) != len(list2) {
		t.Error("Unmarshal has skipped/added entries")
	}
}
