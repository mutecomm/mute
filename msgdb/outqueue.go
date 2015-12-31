// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddOutQueue adds the encrypted message encMsg corresponding to the the
// plain text message with msgID to the outqueue.
func (msgDB *MsgDB) AddOutQueue(
	myID string,
	msgID int64,
	encMsg, nymaddress string,
	minDelay, maxDelay int32,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	var mID int64
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return log.Error(err)
	}
	tx, err := msgDB.encDB.Begin()
	if err != nil {
		return log.Error(err)
	}
	if _, err := tx.Stmt(msgDB.updateDeliveryMsgQuery).Exec(msgID); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	_, err = tx.Stmt(msgDB.addOutQueueQuery).Exec(mID, msgID, encMsg,
		nymaddress, minDelay, maxDelay)
	if err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	return nil
}

// GetOutQueue returns the first entry in the outqueue for myID.
func (msgDB *MsgDB) GetOutQueue(myID string) (
	oqIdx int64,
	msg, nymaddress string,
	minDelay, maxDelay int32,
	envelope bool,
	err error,
) {
	if err := identity.IsMapped(myID); err != nil {
		return 0, "", "", 0, 0, false, log.Error(err)
	}
	var mID int64
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return 0, "", "", 0, 0, false, log.Error(err)
	}
	var e int64
	err = msgDB.getOutQueueQuery.QueryRow(mID).Scan(&oqIdx, &msg, &nymaddress,
		&minDelay, &maxDelay, &e)
	switch {
	case err == sql.ErrNoRows:
		return 0, "", "", 0, 0, false, nil
	case err != nil:
		return 0, "", "", 0, 0, false, log.Error(err)
	}
	if e > 0 {
		envelope = true
	}
	return
}

// SetOutQueue replaces the encrypted message corresponding to oqIdx with the
// envelope message envMsg.
func (msgDB *MsgDB) SetOutQueue(oqIdx int64, envMsg string) error {
	if _, err := msgDB.setOutQueueQuery.Exec(envMsg, oqIdx); err != nil {
		return log.Error(err)
	}
	return nil
}

// RemoveOutQueue remove the message corresponding to oqIdx from the outqueue
// and sets the send time of the corresponding message to date.
func (msgDB *MsgDB) RemoveOutQueue(oqIdx, date int64) error {
	tx, err := msgDB.encDB.Begin()
	if err != nil {
		return log.Error(err)
	}
	var msgID int64
	// get corresponding msgID
	err = tx.Stmt(msgDB.getOutQueueMsgIDQuery).QueryRow(oqIdx).Scan(&msgID)
	if err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	// set date for message
	_, err = tx.Stmt(msgDB.updateMsgDateQuery).Exec(date, 1, msgID)
	if err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	// remove entry from outqueue
	if _, err := tx.Stmt(msgDB.removeOutQueueQuery).Exec(oqIdx); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return log.Error(err)
	}
	return nil
}
