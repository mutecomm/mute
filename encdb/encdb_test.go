// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var passphrase = []byte("passphrase")

const iter int = 4096

func TestCreateOpenClose(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	encdb, err := Open(dbname, passphrase)
	require.NoError(t, err)
	assert.NoError(t, encdb.Close())
}

func TestCreateRekey(t *testing.T) {
	sqls := []string{
		"CREATE TABLE Test (ID INTEGER PRIMARY KEY, Test TEXT);",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, sqls))
	require.NoError(t, Rekey(dbname, passphrase, []byte("newpass"), iter))
}

func TestCreateRekeyFailPass(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, sqls))
	require.Error(t, Rekey(dbname, []byte("wrong"), []byte("newpass"), iter))
}

func TestCreateRekeyFailIter(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, sqls))
	require.Error(t, Rekey(dbname, passphrase, []byte("newpass"), -1))
}

func TestCreateFailSQL(t *testing.T) {
	sqls := []string{
		"create table Bogus",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.Error(t, Create(dbname, passphrase, iter, sqls))
}

func TestCreateFailIter(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.Error(t, Create(dbname, passphrase, -1, nil))
}

func TestCreateOpenFailPass(t *testing.T) {
	sqls := []string{
		"create table Test (ID integer not null primary key, Test text)",
	}
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, sqls))
	_, err = Open(dbname, []byte("wrong"))
	require.Error(t, err)
}

func TestCreateOpenFailKeyfile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	fp, err := os.Create(dbname + ".key")
	require.NoError(t, err)
	fp.Close()
	_, err = Open(dbname, passphrase)
	require.Error(t, err)
}

func TestMultipleCreates(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	require.Error(t, Create(dbname, passphrase, iter, nil), "second create should fail")
	os.Remove(dbname + ".db")
	require.Error(t, Create(dbname, passphrase, iter, nil), "third create should fail")
}

func TestMissingDBFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	os.Remove(dbname + ".db")
	_, err = Open(dbname, passphrase)
	require.Error(t, err, "open should fail (missing dbfile)")
}

func TestMissingKeyFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	os.Remove(dbname + ".key")
	_, err = Open(dbname, passphrase)
	require.Error(t, err, "open should fail (missing keyfile)")
}

func TestCorruptDBFile(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	fp, err := os.Create(dbname + ".db")
	require.NoError(t, err)
	_, err = fp.WriteString("garbage")
	require.NoError(t, err)
	fp.Close()
	_, err = Open(dbname, passphrase)
	require.Error(t, err, "open should fail (corrupt dbfile)")
}

func TestUpkeep(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "encdb_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	dbname := filepath.Join(tmpdir, "encdb_test")
	require.NoError(t, Create(dbname, passphrase, iter, nil))
	encdb, err := Open(dbname, passphrase)
	require.NoError(t, err)
	autoVacuum, freelistCount, err := Status(encdb)
	require.NoError(t, err)
	if autoVacuum != "FULL" {
		t.Error("autoVacuum != \"FULL\"")
	}
	if freelistCount != 0 {
		t.Error("freelistCount != 0")
	}
	assert.Error(t, Incremental(encdb, 0))
	assert.Error(t, Vacuum(encdb, "UNKNOWN"))
	require.NoError(t, Vacuum(encdb, "INCREMENTAL"))
	require.NoError(t, Incremental(encdb, 0))
	require.NoError(t, Vacuum(encdb, ""))
	assert.NoError(t, encdb.Close())
}
