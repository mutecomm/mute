// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
)

// AddSessionKey adds a session key to keyDB.
func (keyDB *KeyDB) AddSessionKey(
	hash, json, privKey string,
	cleanupTime uint64,
) error {
	if hash == "" {
		return log.Error("keydb: hash must be defined")
	}
	if json == "" {
		return log.Error("keydb: json must be defined")
	}
	if privKey == "" {
		return log.Error("keydb: privKey must be defined")
	}
	_, err := keyDB.insertSessionKeyQuery.Exec(hash, json, privKey, cleanupTime)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

// GetSessionKey retrieves the session key with given hash from keyDB.
func (keyDB *KeyDB) GetSessionKey(hash string) (
	json, privKey string,
	err error,
) {
	if hash == "" {
		return "", "", log.Error("keydb: hash must be defined")
	}
	err = keyDB.getSessionKeyQuery.QueryRow(hash).Scan(&json, &privKey)
	switch {
	case err == sql.ErrNoRows:
		return "", "", sql.ErrNoRows
	case err != nil:
		return "", "", log.Error(err)
	}
	return
}

// DelPrivSessionKey deletes the private key corresponding to the session key
// with given hash from keyDB.
func (keyDB *KeyDB) DelPrivSessionKey(hash string) error {
	if hash == "" {
		return log.Error("keydb: hash must be defined")
	}
	_, err := keyDB.updateSessionKeyQuery.Exec("", hash)
	if err != nil {
		return log.Error(err)
	}
	return nil
}
