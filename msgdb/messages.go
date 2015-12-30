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

// AddMessage adds message between selfID and peerID to msgDB. If sent is
// true, it is a sent message. Otherwise a received message.
func (msgDB *MsgDB) AddMessage(
	selfID, peerID string,
	sent bool,
	message string,
	sign bool,
	minDelay, maxDelay int32,
) error {
	if err := identity.IsMapped(selfID); err != nil {
		return log.Error(err)
	}
	if err := identity.IsMapped(peerID); err != nil {
		return log.Error(err)
	}
	// get self
	var self int64
	if err := msgDB.getNymUIDQuery.QueryRow(selfID).Scan(&self); err != nil {
		return log.Error(err)
	}
	// get peer
	var peer int64
	if err := msgDB.getContactUIDQuery.QueryRow(self, peerID).Scan(&peer); err != nil {
		return log.Error(err)
	}
	// add message
	var d int64
	if sent {
		d = 1
	}
	var s int64
	if sign {
		s = 1
	}
	var from string
	var to string
	if sent {
		from = selfID
		to = peerID
	} else {
		from = peerID
		to = selfID
	}
	parts := strings.SplitN(message, "\n", 2)
	subject := parts[0]
	_, err := msgDB.addMsgQuery.Exec(self, peer, d, d, from, to, 0, subject,
		message, s, minDelay, maxDelay)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

// GetMessage returns the message with the given msgID.
func (msgDB *MsgDB) GetMessage(
	myID string,
	msgID int64,
) (from, to, msg string, err error) {
	if err := identity.IsMapped(myID); err != nil {
		return "", "", "", log.Error(err)
	}
	var self int64
	var peer int64
	var direction int64
	err = msgDB.getMsgQuery.QueryRow(msgID).Scan(&self, &peer, &direction, &msg)
	if err != nil {
		return "", "", "", err
	}
	var selfID string
	err = msgDB.getNymMappedQuery.QueryRow(self).Scan(&selfID)
	if err != nil {
		return "", "", "", log.Error(err)
	}
	if myID != selfID {
		return "", "", "", log.Error("msgdb: unknown message")
	}
	var peerID string
	err = msgDB.getContactMappedQuery.QueryRow(self, peer).Scan(&peerID)
	if err != nil {
		return "", "", "", log.Error(err)
	}
	if direction == 1 {
		from = selfID
		to = peerID
	} else {
		from = peerID
		to = selfID
	}
	return
}

// MsgID is the info type that is returned by GetMsgIDs.
type MsgID struct {
	MsgID   int64
	From    string
	To      string
	Sent    bool
	Date    int64
	Subject string
}

// GetMsgIDs returns all message IDs (sqlite row IDs) for the user ID myID.
func (msgDB *MsgDB) GetMsgIDs(myID string) ([]*MsgID, error) {
	if err := identity.IsMapped(myID); err != nil {
		return nil, log.Error(err)
	}
	var uid int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&uid); err != nil {
		return nil, log.Error(err)
	}
	rows, err := msgDB.getMsgsQuery.Query(uid)
	if err != nil {
		return nil, log.Error(err)
	}
	var msgIDs []*MsgID
	defer rows.Close()
	for rows.Next() {
		var (
			id      int64
			from    string
			to      string
			d       int64
			date    int64
			subject string
		)
		if err := rows.Scan(&id, &from, &to, &d, &date, &subject); err != nil {
			return nil, log.Error(err)
		}
		var sent bool
		if d > 0 {
			sent = true
		}
		msgIDs = append(msgIDs, &MsgID{
			MsgID:   id,
			From:    from,
			To:      to,
			Sent:    sent,
			Date:    date,
			Subject: subject,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}
	return msgIDs, nil
}

// GetUndeliveredMessage returns the oldest undelivered message for myID from
// msgDB.
func (msgDB *MsgDB) GetUndeliveredMessage(myID string) (
	msgID int64,
	contactID string,
	msg []byte,
	sign bool,
	minDelay, maxDelay int32,
	err error,
) {
	if err := identity.IsMapped(myID); err != nil {
		return 0, "", nil, false, 0, 0, log.Error(err)
	}
	var mID int64
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return 0, "", nil, false, 0, 0, log.Error(err)
	}
	var cID int64
	var s int64
	err = msgDB.getUndeliveredMsgQuery.QueryRow(mID).Scan(&msgID, &cID, &msg,
		&s, &minDelay, &maxDelay)
	switch {
	case err == sql.ErrNoRows:
		return 0, "", nil, false, 0, 0, nil
	case err != nil:
		return 0, "", nil, false, 0, 0, log.Error(err)
	}
	if s > 0 {
		sign = true
	}
	err = msgDB.getContactMappedQuery.QueryRow(mID, cID).Scan(&contactID)
	if err != nil {
		return 0, "", nil, false, 0, 0, log.Error(err)
	}
	return
}

// numberOfMessages returns the number of messages in msgDB.
func (msgDB *MsgDB) numberOfMessages() (int64, error) {
	var num int64
	err := msgDB.encDB.QueryRow("SELECT COUNT(*) FROM Messages;").Scan(&num)
	if err != nil {
		return 0, err
	}
	return num, nil
}
