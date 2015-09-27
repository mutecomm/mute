// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
)

// AddValue adds a key-value pair to keyDB.
func (keyDB *KeyDB) AddValue(key, value string) error {
	if key == "" {
		return log.Error("keydb: key must be defined")
	}
	if value == "" {
		return log.Error("keydb: value must be defined")
	}
	res, err := keyDB.updateValueQuery.Exec(value, key)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := keyDB.insertValueQuery.Exec(key, value)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// GetValue gets the value for the given key from keyDB.
func (keyDB *KeyDB) GetValue(key string) (string, error) {
	if key == "" {
		return "", log.Error("keydb: key must be defined")
	}
	var value string
	err := keyDB.getValueQuery.QueryRow(key).Scan(&value)
	switch {
	case err == sql.ErrNoRows:
		return "", nil
	case err != nil:
		return "", log.Error(err)
	default:
		return value, nil
	}
}
