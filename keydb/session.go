// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddSession adds a session for the given myID contactID pair. A session
// consists of a rootKeyHash, a chainKey and two arrays send and recv of
// sender and receiver keys. The arrays must have the same size.
func (keyDB *KeyDB) AddSession(
	myID, contactID, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if err := identity.IsMapped(contactID); err != nil {
		return log.Error(err)
	}
	if len(send) != len(recv) {
		return log.Error("keydb: len(send) != len(recv)")
	}
	// store/update session
	res, err := keyDB.updateSessionQuery.Exec(rootKeyHash, chainKey, myID, contactID)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := keyDB.insertSessionQuery.Exec(myID, contactID, rootKeyHash, chainKey)
		if err != nil {
			return log.Error(err)
		}
	}
	// stores message keys
	for i := range send {
		_, err := keyDB.addMessageKeyQuery.Exec(
			rootKeyHash,
			i,
			send[i],
			recv[i],
		)
		if err != nil {
			return err
		}

	}
	return nil
}

// GetSession returns the session rootKeyHash for the given identity partner
// pair.
func (keyDB *KeyDB) GetSession(identity, partner string) (string, error) {
	var rootKeyHash string
	err := keyDB.getSessionQuery.QueryRow(identity, partner).Scan(&rootKeyHash)
	switch {
	case err == sql.ErrNoRows:
		return "", nil
	case err != nil:
		return "", log.Error(err)
	default:
		return rootKeyHash, nil
	}
}
