package msgdb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
)

// AddValue adds a key-value pair to msgDB.
func (msgDB *MsgDB) AddValue(key, value string) error {
	if key == "" {
		return log.Error("msgdb: key must be defined")
	}
	if value == "" {
		return log.Error("msgdb: value must be defined")
	}
	res, err := msgDB.updateValueQuery.Exec(value, key)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := msgDB.insertValueQuery.Exec(key, value)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// GetValue gets the value for the given key from msgDB.
func (msgDB *MsgDB) GetValue(key string) (string, error) {
	if key == "" {
		return "", log.Error("msgdb: key must be defined")
	}
	var value string
	err := msgDB.getValueQuery.QueryRow(key).Scan(&value)
	switch {
	case err == sql.ErrNoRows:
		return "", nil
	case err != nil:
		return "", log.Error(err)
	default:
		return value, nil
	}
}
