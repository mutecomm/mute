// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	// generate keyfile
	gkey, err := generateKeyfile(keyfile, passphrase, iter)
	require.NoError(t, err)
	// read keyfile
	rkey, err := ReadKeyfile(keyfile, passphrase)
	require.NoError(t, err)
	// compare keys
	require.Equal(t, gkey, rkey, "keys differ")
}

func TestMultipleGenerates(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	_, err = generateKeyfile(keyfile, passphrase, iter)
	require.NoError(t, err)
	_, err = generateKeyfile(keyfile, passphrase, iter)
	require.Error(t, err, "second generate should fail")
}

func TestFailingRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	_, err = ReadKeyfile(keyfile, passphrase)
	require.Error(t, err)
}

func TestInvalidIterRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	fp, err := os.Create(keyfile)
	require.NoError(t, err)
	var biter = make([]byte, 8)
	for k := range biter {
		biter[k] = 255
	}
	_, err = fp.Write(biter)
	require.NoError(t, err)
	fp.Close()
	_, err = ReadKeyfile(keyfile, passphrase)
	require.Error(t, err)
}

func bogusElementRead(t *testing.T, size int) {
	tmpdir, err := ioutil.TempDir("", "keyfile_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	fp, err := os.Create(keyfile)
	require.NoError(t, err)
	var biter = make([]byte, size)
	_, err = fp.Write(biter)
	require.NoError(t, err)
	fp.Close()
	_, err = ReadKeyfile(keyfile, passphrase)
	require.Error(t, err)
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
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	keyfile := filepath.Join(tmpdir, "keyfile_test.key")
	// generate keyfile
	_, err = generateKeyfile(keyfile, passphrase, -1)
	require.Error(t, err)
}
