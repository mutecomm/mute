// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var passphrase = []byte("passphrase")

const iter int = 4096

func TestCreateOpenClose(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	encdb, err := Open(dbname, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	encdb.Close()
}

func TestCreateRekey(t *testing.T) {
	sqls := []string{
		"CREATE TABLE Test (ID INTEGER PRIMARY KEY, Test TEXT);",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, sqls); err != nil {
		t.Fatal(err)
	}

	if err := Rekey(dbname, passphrase, []byte("newpass"), iter); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRekeyFailPass(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, sqls); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(dbname, []byte("wrong"), []byte("newpass"), iter); err == nil {
		t.Fatalf("rekey should fail")
	}
}

func TestCreateRekeyFailIter(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, sqls); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(dbname, passphrase, []byte("newpass"), -1); err == nil {
		t.Fatalf("rekey should fail")
	}
}

func TestCreateFailSQL(t *testing.T) {
	sqls := []string{
		"create table Bogus",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, sqls); err == nil {
		t.Fatalf("create should fail")
	}
}

func TestCreateFailIter(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, -1, nil); err == nil {
		t.Fatalf("create should fail")
	}
}

func TestCreateOpenFailPass(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, sqls); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dbname, []byte("wrong")); err == nil {
		t.Fatalf("open should fail")
	}
}

func TestCreateOpenFailKeyfile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	fp, err := os.Create(dbname + ".key")
	if err != nil {
		t.Fatal(err)
	}
	fp.Close()
	if _, err := Open(dbname, passphrase); err == nil {
		t.Fatalf("open should fail")
	}
}

func TestMultipleCreates(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	if err = Create(dbname, passphrase, iter, nil); err == nil {
		t.Fatalf("second create should fail")
	}
	os.Remove(dbname + ".db")
	if err = Create(dbname, passphrase, iter, nil); err == nil {
		t.Fatalf("third create should fail")
	}
}

func TestMissingDBFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	os.Remove(dbname + ".db")
	_, err = Open(dbname, passphrase)
	if err == nil {
		t.Fatal("open should fail (missing dbfile)")
	}
}

func TestMissingKeyFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	os.Remove(dbname + ".key")
	_, err = Open(dbname, passphrase)
	if err == nil {
		t.Fatal("open should fail (missing keyfile)")
	}
}

func TestCorruptDBFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	fp, err := os.Create(dbname + ".db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fp.WriteString("garbage"); err != nil {
		t.Fatal(err)
	}
	fp.Close()
	_, err = Open(dbname, passphrase)
	if err == nil {
		t.Fatal("open should fail (corrupt dbfile)")
	}
}

func TestUpkeep(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	if err = Create(dbname, passphrase, iter, nil); err != nil {
		t.Fatal(err)
	}
	encdb, err := Open(dbname, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	autoVacuum, freelistCount, err := Status(encdb)
	if err != nil {
		t.Fatal(err)
	}
	if autoVacuum != "FULL" {
		t.Error("autoVacuum != \"FULL\"")
	}
	if freelistCount != 0 {
		t.Error("freelistCount != 0")
	}
	if err := Incremental(encdb, 0); err == nil {
		t.Error("should fail")
	}
	if err := Vacuum(encdb, "UNKNOWN"); err == nil {
		t.Error("should fail")
	}
	if err := Vacuum(encdb, "INCREMENTAL"); err != nil {
		t.Fatal(err)
	}
	if err := Incremental(encdb, 0); err != nil {
		t.Fatal(err)
	}
	if err := Vacuum(encdb, ""); err != nil {
		t.Fatal(err)
	}
	encdb.Close()
}
