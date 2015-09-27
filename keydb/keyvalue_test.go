// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"os"
	"testing"
)

func TestKeyValueStore(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	// normal add/get cycle
	if err := keyDB.AddValue("foo", "bar"); err != nil {
		t.Fatal(err)
	}
	value, err := keyDB.GetValue("foo")
	if err != nil {
		t.Fatal(err)
	}
	if value != "bar" {
		t.Errorf("value is not \"bar\" (but \"%s\")", value)
	}
	// update key
	if err := keyDB.AddValue("foo", "baz"); err != nil {
		t.Fatal(err)
	}
	value, err = keyDB.GetValue("foo")
	if err != nil {
		t.Fatal(err)
	}
	if value != "baz" {
		t.Errorf("value is not \"baz\" (but \"%s\")", value)
	}
	// add empty key
	if err := keyDB.AddValue("", "bar"); err == nil {
		t.Error("adding empty key should fail")
	}
	// add empty value
	if err := keyDB.AddValue("foo", ""); err == nil {
		t.Error("adding empty value should fail")
	}
	// get empty key
	if value, err := keyDB.GetValue(""); value != "" || err == nil {
		t.Error("getting empty key should fail")
	}
	// get undefined key
	if value, err := keyDB.GetValue("bar"); value != "" || err != nil {
		t.Error("getting undefined key should return empty value")
	}
}
