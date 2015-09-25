package msgdb

import (
	"os"
	"testing"
)

func TestContacts(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	e := "eve@mute.berlin"
	m := "mallory@mute.berlin"
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	num, err := msgDB.numberOfContacts()
	if err != nil {
		t.Fatal(err)
	}
	if num != 0 {
		t.Errorf("num != 0 == %d", num)
	}
	if err := msgDB.AddContact(a, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, e, e, "", BlackList); err != nil {
		t.Fatal(err)
	}
	num, err = msgDB.numberOfContacts()
	if err != nil {
		t.Fatal(err)
	}
	if num != 2 {
		t.Errorf("num != 2 == %d", num)
	}
	unmappedID, fullName, contactType, err := msgDB.GetContact(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if unmappedID != b {
		t.Error("unmappedID != b")
	}
	if fullName != "Bob" {
		t.Error("fullName != \"Bob\"")
	}
	if contactType != WhiteList {
		t.Error("should not white listed")
	}
	unmappedID, fullName, contactType, err = msgDB.GetContact(a, e)
	if err != nil {
		t.Fatal(err)
	}
	if unmappedID != e {
		t.Error("unmappedID != e")
	}
	if fullName != "" {
		t.Error("fullName != \"\"")
	}
	if contactType != BlackList {
		t.Error("should be black listed")
	}
	contacts, err := msgDB.GetContacts(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	}
	if contacts[0] != "Bob <"+b+">" {
		t.Error("contacts[0] != Bob <bob@mute.berlin>")
	}
	contacts, err = msgDB.GetContacts(a, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	}
	if contacts[0] != e {
		t.Error("contacts[0] != e")
	}
	if err := msgDB.AddContact(a, m, m, "", WhiteList); err != nil {
		t.Fatal(err)
	}
	contacts, err = msgDB.GetContacts(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 {
		t.Error("len(contacts) != 2")
	}
	if err := msgDB.AddContact(a, m, m, "", BlackList); err != nil {
		t.Fatal(err)
	}
	contacts, err = msgDB.GetContacts(a, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 {
		t.Error("len(contacts) != 2")
	}
	if err := msgDB.RemoveContact(a, b); err != nil {
		t.Fatal(err)
	}
	_, _, contactType, err = msgDB.GetContact(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if contactType != GrayList {
		t.Error("should be gray listed")
	}
	if err := msgDB.RemoveContact(a, e); err != nil {
		t.Fatal(err)
	}
	_, _, contactType, err = msgDB.GetContact(a, e)
	if err != nil {
		t.Fatal(err)
	}
	if contactType != GrayList {
		t.Error("should be gray listed")
	}
	if err := msgDB.RemoveContact(a, m); err != nil {
		t.Fatal(err)
	}
	contacts, err = msgDB.GetContacts(a, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 0 {
		t.Error("len(contacts) != 0")
	}
	// an unknown entry doesn't trigger an error
	if err := msgDB.RemoveContact(a, "unknown@mute.berlin"); err != nil {
		t.Fatal(err)
	}
}

func TestContactList(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	e := "eve@mute.berlin"
	if err := msgDB.AddNym(b, b, "Bob"); err != nil {
		t.Fatal(err)
	}
	// add alice to bob
	if err := msgDB.AddContact(b, a, a, "", WhiteList); err != nil {
		t.Fatal(err)
	}
	// list bob's contacts
	contacts, err := msgDB.GetContacts(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	}
	if contacts[0] != a {
		t.Error("contacts[0] != a")
	}
	// block eve for bob
	if err := msgDB.AddContact(b, e, e, "", BlackList); err != nil {
		t.Fatal(err)
	}
	// get bob's blacklist
	contacts, err = msgDB.GetContacts(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	}
	if contacts[0] != e {
		t.Error("contacts[0] != e")
	}
	// unblock eve
	if err := msgDB.AddContact(b, e, e, "", WhiteList); err != nil {
		t.Fatal(err)
	}
	// get bob's blacklist
	contacts, err = msgDB.GetContacts(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 0 {
		t.Error("len(contacts) != 0")
	}
	// list bob's contacts
	contacts, err = msgDB.GetContacts(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 {
		t.Error("len(contacts) != 2")
	}
	// remove eve
	if err := msgDB.RemoveContact(b, e); err != nil {
		t.Fatal(err)
	}
	// list bob's contacts
	contacts, err = msgDB.GetContacts(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Error("len(contacts) != 1")
	}
	if contacts[0] != a {
		t.Error("contacts[0] != a")
	}
}
