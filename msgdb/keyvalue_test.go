package msgdb

import (
	"os"
	"testing"
)

func TestKeyValueStore(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	// normal add/get cycle
	if err := msgDB.AddValue("foo", "bar"); err != nil {
		t.Fatal(err)
	}
	value, err := msgDB.GetValue("foo")
	if err != nil {
		t.Fatal(err)
	}
	if value != "bar" {
		t.Errorf("value is not \"bar\" (but \"%s\")", value)
	}
	// update key
	if err := msgDB.AddValue("foo", "baz"); err != nil {
		t.Fatal(err)
	}
	value, err = msgDB.GetValue("foo")
	if err != nil {
		t.Fatal(err)
	}
	if value != "baz" {
		t.Errorf("value is not \"baz\" (but \"%s\")", value)
	}
	// add empty key
	if err := msgDB.AddValue("", "bar"); err == nil {
		t.Error("adding empty key should fail")
	}
	// add empty value
	if err := msgDB.AddValue("foo", ""); err == nil {
		t.Error("adding empty value should fail")
	}
	// get empty key
	if value, err := msgDB.GetValue(""); value != "" || err == nil {
		t.Error("getting empty key should fail")
	}
	// get undefined key
	if value, err := msgDB.GetValue("bar"); value != "" || err != nil {
		t.Error("getting undefined key should return empty value")
	}
}
