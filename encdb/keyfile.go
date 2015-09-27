// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encdb

import (
	"crypto/sha256"
	"io"
	"os"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode"
	"github.com/mutecomm/mute/log"
	"golang.org/x/crypto/pbkdf2"
)

/*
The keyfile implemented by this package provides a randomly generated AES-256
key stored in a file which itself is encrypted by AES-256.

Format of keyfile:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  number of iterations for PBKDF2              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        salt for PBKDF2                        |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            IV for                             |
|                       AES-256 encryption                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            AES-256                            |
|                           encrypted                           |
|                          AES-256 key                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// writeKeyFile writes a key file with the given filename that contains the
// supplied key in AES-256 encrypted form.
func writeKeyfile(filename string, passphrase []byte, iter int, key []byte) error {
	// make sure keyfile does not exist already
	if _, err := os.Stat(filename); err == nil {
		return log.Errorf("encdb: keyfile '%s' exists already", filename)
	}
	// convert iter to uint64
	var uiter uint64
	if iter < 0 || iter > 2147483647 {
		return log.Errorf("encdb: writeKeyfile: invalid iter value")
	}
	uiter = uint64(iter)
	// check keylength
	if len(key) != 32 {
		return log.Errorf("encdb: writeKeyfile: len(key) != 32")
	}
	// create keyfile
	keyfile, err := os.Create(filename)
	if err != nil {
		return log.Error(err)
	}
	defer keyfile.Close()
	// generate salt
	var salt = make([]byte, 32)
	if _, err := io.ReadFull(cipher.RandReader, salt); err != nil {
		return err
	}
	// compute derived key from passphrase
	dk := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)
	// compute AES-256 encrypted key (with IV)
	encKey := cipher.AES256CBCEncrypt([]byte(dk), key, cipher.RandReader)
	// write number of iterations
	if _, err := keyfile.Write(encode.ToByte8(uiter)); err != nil {
		return err
	}
	// write salt
	if _, err := keyfile.Write(salt); err != nil {
		return err
	}
	// write IV and AES-256 encrypted key
	if _, err := keyfile.Write(encKey); err != nil {
		return err
	}
	return nil
}

// generateKeyFile generates a key file with the given filename that contains a
// randomly generated and encrypted AES-256 key.
// The generated key is protected by a passphrase, which is processed by PBKDF2
// with iter many iterations to derive the AES-256 key to encrypt the generated
// key. The function returns the generated key in unencrypted form.
func generateKeyfile(filename string, passphrase []byte, iter int) (key []byte, err error) {
	// generate raw key
	var rawKey = make([]byte, 32)
	if _, err := io.ReadFull(cipher.RandReader, rawKey); err != nil {
		return nil, err
	}
	if err := writeKeyfile(filename, passphrase, iter, rawKey); err != nil {
		return nil, err
	}
	return rawKey, nil
}

// readKeyFile reads a randomly generated and encrypted AES-256 key from the
// file with the given filename and returns it in unencrypted form.
// The key is protected by a passphrase, which is processed by PBKDF2 to
// derive the AES-256 key to decrypt the generated key.
func readKeyfile(filename string, passphrase []byte) (key []byte, err error) {
	// open keyfile
	keyfile, err := os.Open(filename)
	if err != nil {
		return nil, log.Error(err)
	}
	defer keyfile.Close()
	// read iter and convert to int
	var biter = make([]byte, 8)
	if _, err := keyfile.Read(biter); err != nil {
		return nil, log.Error(err)
	}
	uiter := encode.ToUint64(biter)
	if uiter > 2147483647 {
		return nil, log.Errorf("encdb: readKeyfile: invalid iter value")
	}
	iter := int(uiter)
	// read salt
	var salt = make([]byte, 32)
	if _, err := keyfile.Read(salt); err != nil {
		return nil, log.Error(err)
	}
	// read encrypted key
	var encKey = make([]byte, 16+32)
	if _, err := keyfile.Read(encKey); err != nil {
		return nil, log.Error(err)
	}
	// compute derived key from passphrase
	dk := pbkdf2.Key([]byte(passphrase), salt, iter, 32, sha256.New)
	// decrypt key
	return cipher.AES256CBCDecrypt([]byte(dk), encKey), nil
}

func replaceKeyfile(filename string, oldPassphrase, newPassphrase []byte, newIter int) error {
	key, err := readKeyfile(filename, oldPassphrase)
	if err != nil {
		return err
	}
	tmpfile := filename + ".new"
	os.Remove(tmpfile) // ignore error
	if err := writeKeyfile(tmpfile, newPassphrase, newIter, key); err != nil {
		return err
	}
	return os.Rename(tmpfile, filename)
}
