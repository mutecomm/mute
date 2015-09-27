// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/mutecomm/mute/cipher"
)

func createDB() (tmpdir string, msgDB *MsgDB, err error) {
	tmpdir, err = ioutil.TempDir("", "msgdb_test")
	if err != nil {
		return "", nil, err
	}
	dbname := path.Join(tmpdir, "msgdb")
	passphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Create(dbname, passphrase, 64000); err != nil {
		return "", nil, err
	}
	msgDB, err = Open(dbname, passphrase)
	if err != nil {
		return "", nil, err
	}
	return
}

func TestHelper(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	if msgDB.DB() != msgDB.encDB {
		t.Error("msgDB.DB() != msgDB.encDB")
	}
	version, err := msgDB.version()
	if err != nil {
		t.Fatal(err)
	}
	if version != Version {
		t.Errorf("msgDB.version() != %s", Version)
	}
}

func TestRekey(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "msgdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := path.Join(tmpdir, "msgdb")
	passphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Create(dbname, passphrase, 64000); err != nil {
		t.Fatal(err)
	}
	msgDB, err := Open(dbname, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	msgDB.Close()
	newPassphrase := []byte(cipher.RandPass(cipher.RandReader))
	if err := Rekey(dbname, passphrase, newPassphrase, 32000); err != nil {
		t.Fatal(err)
	}
	msgDB, err = Open(dbname, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgDB.Close(); err != nil {
		t.Fatal(err)
	}
}
