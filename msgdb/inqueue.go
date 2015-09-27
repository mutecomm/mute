// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"database/sql"
	"strings"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddInQueue adds the given message corressponding to myID and contactID (can
// be nil) to the inqueue.
func (msgDB *MsgDB) AddInQueue(myID, contactID string, date int64, msg string) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
	}
	var mID int64
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return log.Error(err)
	}
	var cID int64
	if contactID != "" {
		if err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID); err != nil {
			return log.Error(err)
		}
	}
	if _, err := msgDB.addInQueueQuery.Exec(mID, cID, date, msg); err != nil {
		return log.Error(err)
	}
	return nil
}

// GetInQueue returns the first entry in the inqueue.
func (msgDB *MsgDB) GetInQueue() (
	iqIdx int64,
	myID, contactID, msg string,
	envelope bool,
	err error,
) {
	var mID int64
	var cID int64
	var env int64
	err = msgDB.getInQueueQuery.QueryRow().Scan(&iqIdx, &mID, &cID, &msg, &env)
	switch {
	case err == sql.ErrNoRows:
		return 0, "", "", "", false, nil
	case err != nil:
		return 0, "", "", "", false, log.Error(err)
	}
	err = msgDB.getNymMappedQuery.QueryRow(mID).Scan(&myID)
	if err != nil {
		return 0, "", "", "", false, log.Error(err)
	}
	if cID > 0 {
		err = msgDB.getContactMappedQuery.QueryRow(mID, cID).Scan(&contactID)
		if err != nil {
			return 0, "", "", "", false, log.Error(err)
		}
	}
	if env > 0 {
		envelope = true
	}
	return
}

// SetInQueue replaces the encrypted message corresponding to iqIdx with the
// encrypted message msg.
func (msgDB *MsgDB) SetInQueue(iqIdx int64, msg string) error {
	if _, err := msgDB.setInQueueQuery.Exec(msg, iqIdx); err != nil {
		return log.Error(err)
	}
	return nil
}

// RemoveInQueue remove the entry with index iqIdx from inqueue and adds the
// descrypted message plainMsg to msgDB (if drop is not true).
func (msgDB *MsgDB) RemoveInQueue(
	iqIdx int64, plainMsg, fromID string,
	drop bool,
) error {
	if err := identity.IsMapped(fromID); err != nil {
		return log.Error(err)
	}
	var mID int64
	var cID int64
	var date int64
	err := msgDB.getInQueueIDsQuery.QueryRow(iqIdx).Scan(&mID, &cID, &date)
	if err != nil {
		return log.Error(err)
	}
	err = msgDB.getContactUIDQuery.QueryRow(mID, fromID).Scan(&cID)
	if err != nil {
		return log.Error(err)
	}
	tx, err := msgDB.encDB.Begin()
	if err != nil {
		return log.Error(err)
	}
	var to string
	if err := tx.Stmt(msgDB.getNymMappedQuery).QueryRow(mID).Scan(&to); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	// TODO: handle signatures
	parts := strings.SplitN(plainMsg, "\n", 2)
	subject := parts[0]
	if !drop {
		_, err = tx.Stmt(msgDB.addMsgQuery).Exec(mID, cID, 0, 0, fromID, to, date, subject, plainMsg, 0, 0, 0)
		if err != nil {
			tx.Rollback()
			return log.Error(err)
		}
	}
	if _, err := tx.Stmt(msgDB.removeInQueueQuery).Exec(iqIdx); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	return nil
}

// DeleteInQueue deletes the entry  with index iqIdx from inqueue.
func (msgDB *MsgDB) DeleteInQueue(iqIdx int64) error {
	if _, err := msgDB.removeInQueueQuery.Exec(iqIdx); err != nil {
		return log.Error(err)
	}
	return nil
}
