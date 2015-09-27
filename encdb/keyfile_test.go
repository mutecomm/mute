// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encdb

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestGenerateRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	// generate keyfile
	gkey, err := generateKeyfile(keyfile, passphrase, iter)
	if err != nil {
		t.Fatal(err)
	}
	// read keyfile
	rkey, err := readKeyfile(keyfile, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	// compare keys
	if !bytes.Equal(gkey, rkey) {
		t.Fatalf("keys differ")
	}
}

func TestMultipleGenerates(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	if _, err := generateKeyfile(keyfile, passphrase, iter); err != nil {
		t.Fatal(err)
	}
	if _, err := generateKeyfile(keyfile, passphrase, iter); err == nil {
		t.Fatalf("second generate should fail")
	}
}

func TestFailingRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	if _, err := readKeyfile(keyfile, passphrase); err == nil {
		t.Fatal("read should fail")
	}
}

func TestInvalidIterRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	fp, err := os.Create(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	var biter = make([]byte, 8)
	for k := range biter {
		biter[k] = 255
	}
	if _, err := fp.Write(biter); err != nil {
		t.Fatal(err)
	}
	fp.Close()
	if _, err := readKeyfile(keyfile, passphrase); err == nil {
		t.Fatalf("read should fail")
	}
}

func bogusElementRead(t *testing.T, size int) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	fp, err := os.Create(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	var biter = make([]byte, size)
	if _, err := fp.Write(biter); err != nil {
		t.Fatal(err)
	}
	fp.Close()
	if _, err := readKeyfile(keyfile, passphrase); err == nil {
		t.Fatalf("read should fail")
	}
}

func TestBogusIterRead(t *testing.T) {
	bogusElementRead(t, 0)
}

func TestBogusSaltRead(t *testing.T) {
	bogusElementRead(t, 8)
}

func TestBogusKeyRead(t *testing.T) {
	bogusElementRead(t, 32)
}

func TestInvalidIterGenerate(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	keyfile := path.Join(tmpdir, "keyfile_test.key")
	// generate keyfile
	if _, err := generateKeyfile(keyfile, passphrase, -1); err == nil {
		t.Fatalf("generate should fail")
	}
}
