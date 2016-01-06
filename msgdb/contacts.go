// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// ContactType represents the different types of contacts
// (white list, gray list, and black list).
type ContactType int64

const (
	// WhiteList represents a white listed contact.
	WhiteList ContactType = iota
	// GrayList represents a gray listed contact.
	GrayList
	// BlackList represents a black listed contact.
	BlackList
)

// AddContact adds or updates a contact in msgDB.
func (msgDB *MsgDB) AddContact(
	myID, mappedID, unmappedID, fullName string,
	contactType ContactType,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if err := identity.IsMapped(mappedID); err != nil {
		return log.Error(err)
	}
	if unmappedID == "" {
		return log.Error("msgdb: unmappedID must be defined")
	}
	// make sure mappedID and unmappedID fit together
	mID, err := identity.Map(unmappedID)
	if err != nil {
		return log.Error(err)
	}
	if mID != mappedID {
		return log.Errorf("msgdb: identity.Map(%s) != %s", unmappedID, mappedID)
	}
	// get MyID
	var uid int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&uid); err != nil {
		return log.Error(err)
	}
	// add contact
	res, err := msgDB.updateContactQuery.Exec(unmappedID, fullName, contactType,
		uid, mappedID)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := msgDB.insertContactQuery.Exec(uid, mappedID, unmappedID,
			fullName, contactType)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// GetContact retrieves the (possibly blocked) contact contactID for myID.
func (msgDB *MsgDB) GetContact(myID, contactID string) (
	unmappedID, fullName string,
	contactType ContactType,
	err error,
) {
	if err := identity.IsMapped(myID); err != nil {
		return "", "", WhiteList, log.Error(err)
	}
	if err := identity.IsMapped(contactID); err != nil {
		return "", "", WhiteList, log.Error(err)
	}
	// get MyID
	var uid int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&uid); err != nil {
		return "", "", WhiteList, log.Error(err)
	}
	// get contacts
	var ct int64
	err = msgDB.getContactQuery.QueryRow(uid, contactID).Scan(&unmappedID,
		&fullName, &ct)
	switch {
	case err == sql.ErrNoRows:
		return "", "", WhiteList, nil
	case err != nil:
		return "", "", WhiteList, log.Error(err)
	}
	switch ct {
	case 0:
		contactType = WhiteList
	case 1:
		contactType = GrayList
	case 2:
		contactType = BlackList
	default:
		return "", "", WhiteList, log.Error("msgdb: unknown contact type found")
	}
	return
}

// GetContacts retrieves all the contacts list (or blacklist, if blocked
// equals true) for the given ownID user ID.
func (msgDB *MsgDB) GetContacts(myID string, blocked bool) ([]string, error) {
	if err := identity.IsMapped(myID); err != nil {
		return nil, log.Error(err)
	}
	// get MyID
	var uid int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&uid); err != nil {
		return nil, log.Error(err)
	}
	var b int
	if blocked {
		b = 2
	}
	// get contacts
	rows, err := msgDB.getContactsQuery.Query(uid, b)
	if err != nil {
		return nil, log.Error(err)
	}
	var contacts []string
	defer rows.Close()
	for rows.Next() {
		var unmappedID, fullName string
		if err := rows.Scan(&unmappedID, &fullName); err != nil {
			return nil, log.Error(err)
		}
		if fullName == "" {
			contacts = append(contacts, unmappedID)
		} else {
			contacts = append(contacts, fullName+" <"+unmappedID+">")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}
	return contacts, nil
}

// RemoveContact removes a contact between myID and contactID (normal or
// blocked) from the msgDB.
func (msgDB *MsgDB) RemoveContact(myID, contactID string) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if err := identity.IsMapped(contactID); err != nil {
		return log.Error(err)
	}
	// get MyID
	var uid int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&uid); err != nil {
		return log.Error(err)
	}
	// delete contact (-> gray list)
	if _, err := msgDB.delContactQuery.Exec(uid, contactID); err != nil {
		return log.Error(err)
	}
	return nil
}

// numberOfContacts returns the number of contacts in msgDB.
func (msgDB *MsgDB) numberOfContacts() (int64, error) {
	var num int64
	err := msgDB.encDB.QueryRow("SELECT COUNT(*) FROM Contacts;").Scan(&num)
	if err != nil {
		return 0, err
	}
	return num, nil
}
