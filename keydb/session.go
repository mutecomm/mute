// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
)

// AddSession adds a session for the given sessionKey. A session
// consists of a rootKeyHash, a chainKey and two arrays send and recv of
// sender and receiver keys. The arrays must have the same size.
func (keyDB *KeyDB) AddSession(
	sessionKey, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if sessionKey == "" {
		return log.Error("keydb: sessionKey must be defined")
	}
	if rootKeyHash == "" {
		return log.Error("keydb: rootKeyHash must be defined")
	}
	if chainKey == "" {
		return log.Error("keydb: chainKey must be defined")
	}
	if len(send) != len(recv) {
		return log.Error("keydb: len(send) != len(recv)")
	}

	// start transaction
	tx, err := keyDB.encDB.Begin()
	if err != nil {
		return log.Error(err)
	}

	var res sql.Result
	_, _, offset, err := keyDB.GetSession(sessionKey)
	switch {
	case err == sql.ErrNoRows:
		// store new session
		res, err = tx.Stmt(keyDB.insertSessionQuery).Exec(sessionKey,
			rootKeyHash, chainKey, len(send))
		if err != nil {
			tx.Rollback()
			return log.Error(err)
		}
	case err != nil:
		tx.Rollback()
		return log.Error(err)
	default:
		// update session
		res, err = tx.Stmt(keyDB.updateSessionQuery).Exec(chainKey,
			offset+uint64(len(send)), sessionKey)
		if err != nil {
			tx.Rollback()
			return log.Error(err)
		}
	}

	// get session ID
	sessionID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return log.Error(err)
	}

	// stores message keys
	for i := range send {
		_, err = tx.Stmt(keyDB.addMessageKeyQuery).Exec(sessionID,
			offset+uint64(i), send[i], 1)
		if err != nil {
			tx.Rollback()
			return log.Error(err)
		}
		_, err = tx.Stmt(keyDB.addMessageKeyQuery).Exec(sessionID,
			offset+uint64(i), recv[i], 0)
		if err != nil {
			tx.Rollback()
			return log.Error(err)
		}
	}

	// commit transaction
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return log.Error(err)
	}

	return nil
}

// GetSession returns the session for the given sessionKey.
func (keyDB *KeyDB) GetSession(sessionKey string) (
	rootKeyHash string,
	chainKey string,
	numOfKeys uint64,
	err error,
) {
	var n int64
	err = keyDB.getSessionQuery.QueryRow(sessionKey).Scan(&rootKeyHash, &chainKey, &n)
	switch {
	case err == sql.ErrNoRows:
		return "", "", 0, sql.ErrNoRows
	case err != nil:
		return "", "", 0, log.Error(err)
	}
	numOfKeys = uint64(n)
	return
}

// GetMessageKey returns the message key for the given sessionKey.
func (keyDB *KeyDB) GetMessageKey(
	sessionKey string,
	sender bool,
	msgIndex uint64,
) (string, error) {
	var sessionID int64
	err := keyDB.getSessionIDQuery.QueryRow(sessionKey).Scan(&sessionID)
	if err != nil {
		return "", err
	}
	var d int64
	if sender {
		d = 1
	}
	var key string
	err = keyDB.getMessageKeyQuery.QueryRow(sessionID, msgIndex, d).Scan(&key)
	if err != nil {
		return "", err
	}
	return key, nil
}

// DelMessageKey deletes the message key for the given sessionKey.
func (keyDB *KeyDB) DelMessageKey(
	sessionKey string,
	sender bool,
	msgIndex uint64,
) error {
	var sessionID int64
	err := keyDB.getSessionIDQuery.QueryRow(sessionKey).Scan(&sessionID)
	if err != nil {
		return err
	}
	var d int64
	if sender {
		d = 1
	}
	_, err = keyDB.delMessageKeyQuery.Exec(sessionID, msgIndex, d)
	if err != nil {
		return err
	}
	return nil
}
