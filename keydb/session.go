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
	// store session
	// TODO: allow to update session
	res, err := keyDB.insertSessionQuery.Exec(sessionKey, rootKeyHash, chainKey)
	if err != nil {
		return log.Error(err)
	}
	// get session ID
	sessionID, err := res.LastInsertId()
	if err != nil {
		return log.Error(err)
	}
	// stores message keys
	// TODO: key numbering for updates!
	for i := range send {
		_, err = keyDB.addMessageKeyQuery.Exec(sessionID, i, send[i], 0)
		if err != nil {
			return log.Error(err)
		}
		_, err = keyDB.addMessageKeyQuery.Exec(sessionID, i, recv[i], 1)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// GetSession returns the session rootKeyHash for the given sessionKey.
func (keyDB *KeyDB) GetSession(sessionKey string) (string, error) {
	var rootKeyHash string
	err := keyDB.getSessionQuery.QueryRow(sessionKey).Scan(&rootKeyHash)
	switch {
	case err == sql.ErrNoRows:
		return "", nil
	case err != nil:
		return "", log.Error(err)
	default:
		return rootKeyHash, nil
	}
}
