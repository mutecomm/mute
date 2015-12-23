// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"crypto/sha512"
	"database/sql"
	"io"
	"os"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/msg"
	"golang.org/x/crypto/hkdf"
)

func deriveKeys(chainKey []byte, kdf io.Reader) (send, recv []string, err error) {
	buffer := make([]byte, 64)
	for i := 0; i < msg.NumOfFutureKeys; i++ {
		if _, err := io.ReadFull(kdf, buffer); err != nil {
			return nil, nil, err
		}
		send = append(send, base64.Encode(cipher.HMAC(chainKey, buffer)))
		if _, err := io.ReadFull(kdf, buffer); err != nil {
			return nil, nil, err
		}
		recv = append(recv, base64.Encode(cipher.HMAC(chainKey, buffer)))
	}
	return
}
func TestSessions(t *testing.T) {
	tmpdir, keyDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer keyDB.Close()
	// make sure sessions are empty initially
	sessionKey := base64.Encode(cipher.SHA512([]byte("key")))
	rootKeyHash, _, _, err := keyDB.GetSession(sessionKey)
	if err != sql.ErrNoRows {
		t.Error("should fail with sql.ErrNoRows")
	}
	if rootKeyHash != "" {
		t.Error("rootKeyHash is supposed to be empty")
	}
	// store root key hash
	rk := base64.Encode(cipher.SHA256([]byte("rootkey")))
	master := make([]byte, 96)
	if _, err := io.ReadFull(cipher.RandReader, master); err != nil {
		t.Fatal(err)
	}
	kdf := hkdf.New(sha512.New, master, nil, nil)
	chainKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, chainKey); err != nil {
		t.Fatal(err)
	}
	send, recv, err := deriveKeys(chainKey, kdf)
	if err != nil {
		t.Fatal(err)
	}
	err = keyDB.AddSession(sessionKey, rk, base64.Encode(chainKey), send, recv)
	if err != nil {
		t.Fatal(err)
	}
	// check root key hash
	rootKeyHash, _, n, err := keyDB.GetSession(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyHash != rk {
		t.Error("rootKeyHash is supposed to equal rk")
	}
	if n != msg.NumOfFutureKeys {
		t.Error("n is supposed to equal msg.NumOfFutureKeys")
	}
	// update root key hash
	chainKey = make([]byte, 32)
	if _, err := io.ReadFull(kdf, chainKey); err != nil {
		t.Fatal(err)
	}
	send, recv, err = deriveKeys(chainKey, kdf)
	if err != nil {
		t.Fatal(err)
	}
	err = keyDB.AddSession(sessionKey, rk, base64.Encode(chainKey), send, recv)
	if err != nil {
		t.Fatal(err)
	}
	// check updated root key hash
	rootKeyHash, _, n, err = keyDB.GetSession(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyHash != rk {
		t.Error("rootKeyHash is supposed to equal rk")
	}
	if n != 2*msg.NumOfFutureKeys {
		t.Error("n is supposed to equal 2*msg.NumOfFutureKeys")
	}

	// TODO: improve tests for message keys
	_, err = keyDB.GetMessageKey(sessionKey, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyDB.DelMessageKey(sessionKey, true, 0); err != nil {
		t.Fatal(err)
	}
}
