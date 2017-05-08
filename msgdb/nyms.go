// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddNym adds or updates a mapping from a mapped ID to an unmapped ID and
// full name.
func (msgDB *MsgDB) AddNym(mappedID, unmappedID, fullName string) error {
	if mappedID == "" {
		return log.Error("msgdb: mappedID must be defined")
	}
	if unmappedID == "" {
		return log.Error("msgdb: unmappedID must be defined")
	}
	// make sure the mappedID is mapped
	if err := identity.IsMapped(mappedID); err != nil {
		return log.Error(err)
	}
	// make sure mappedID and unmappedID fit together
	mID, err := identity.Map(unmappedID)
	if err != nil {
		return log.Error(err)
	}
	if mID != mappedID {
		return log.Errorf("msgdb: identity.Map(%s) != %s", unmappedID, mappedID)
	}
	// fullName can be empty
	res, err := msgDB.updateNymQuery.Exec(unmappedID, fullName, mappedID)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := msgDB.insertNymQuery.Exec(mappedID, unmappedID, fullName)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// GetNym gets the unmapped ID and (full) name for a mapped ID.
func (msgDB *MsgDB) GetNym(mappedID string) (
	unmappedID, fullName string,
	err error,
) {
	// make sure the mappedID is mapped
	if err := identity.IsMapped(mappedID); err != nil {
		return "", "", log.Error(err)
	}
	err = msgDB.getNymQuery.QueryRow(mappedID).Scan(&unmappedID, &fullName)
	switch {
	case err == sql.ErrNoRows:
		return "", "", nil
	case err != nil:
		return "", "", log.Error(err)
	default:
		return
	}
}

// GetNyms returns all unmapped or mapped nyms in msgDB.
func (msgDB *MsgDB) GetNyms(mapped bool) ([]string, error) {
	// get contacts
	rows, err := msgDB.getNymsQuery.Query()
	if err != nil {
		return nil, log.Error(err)
	}
	var nyms []string
	defer rows.Close()
	for rows.Next() {
		var mappedID, unmappedID, fullName string
		if err := rows.Scan(&mappedID, &unmappedID, &fullName); err != nil {
			return nil, log.Error(err)
		}
		if mapped {
			nyms = append(nyms, mappedID)
		} else {
			if fullName == "" {
				nyms = append(nyms, unmappedID)
			} else {
				nyms = append(nyms, fullName+" <"+unmappedID+">")
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}
	return nyms, nil
}

// DelNym deletes the nym mappedID and all associated contacts and messages!
func (msgDB *MsgDB) DelNym(mappedID string) error {
	if err := identity.IsMapped(mappedID); err != nil {
		return log.Error(err)
	}
	unmappedID, _, err := msgDB.GetNym(mappedID)
	if err != nil {
		return err
	}
	if unmappedID == "" {
		return log.Errorf("msgdb: nym %s unknown", mappedID)
	}
	if _, err := msgDB.delNymQuery.Exec(mappedID); err != nil {
		return log.Error(err)
	}
	return nil
}

// GetUpkeepAll retrieves the last execution time of 'upkeep all'.
func (msgDB *MsgDB) GetUpkeepAll(myID string) (int64, error) {
	if err := identity.IsMapped(myID); err != nil {
		return 0, log.Error(err)
	}
	var t int64
	if err := msgDB.getUpkeepAllQuery.QueryRow(myID).Scan(&t); err != nil {
		return 0, log.Error(err)
	}
	return t, nil
}

// SetUpkeepAll sets the last execution time of 'upkeep all' to t.
func (msgDB *MsgDB) SetUpkeepAll(myID string, t int64) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if _, err := msgDB.setUpkeepAllQuery.Exec(t, myID); err != nil {
		return log.Error(err)
	}
	return nil
}

// GetUpkeepAccounts retrieves the last execution time of 'upkeep accounts'.
func (msgDB *MsgDB) GetUpkeepAccounts(myID string) (int64, error) {
	if err := identity.IsMapped(myID); err != nil {
		return 0, log.Error(err)
	}
	var t int64
	if err := msgDB.getUpkeepAccountsQuery.QueryRow(myID).Scan(&t); err != nil {
		return 0, log.Error(err)
	}
	return t, nil
}

// SetUpkeepAccounts sets the last execution time of 'upkeep accounts' to t.
func (msgDB *MsgDB) SetUpkeepAccounts(myID string, t int64) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if _, err := msgDB.setUpkeepAccountsQuery.Exec(t, myID); err != nil {
		return log.Error(err)
	}
	return nil
}
