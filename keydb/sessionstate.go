// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

// GetSessionState retrieves the session state for sessionStateKey from keyDB.
func (keyDB *KeyDB) GetSessionState(sessionStateKey string) (
	*session.State,
	error,
) {
	if sessionStateKey == "" {
		return nil, log.Error("keydb: sessionStateKey must be defined")
	}
	var (
		senderSessionCount          int64
		senderMessageCount          int64
		maxRecipientCount           int64
		recipientTemp               string
		senderSessionPub            string
		nextSenderSessionPub        string
		nextRecipientSessionPubSeen string
		nymAddress                  string
		keyInitSession              int64
	)
	err := keyDB.getSessionStateQuery.QueryRow(sessionStateKey).Scan(&senderSessionCount,
		&senderMessageCount, &maxRecipientCount, &recipientTemp,
		&senderSessionPub, &nextSenderSessionPub, &nextRecipientSessionPubSeen,
		&nymAddress, &keyInitSession)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		return nil, log.Error(err)
	}
	rt, err := uid.NewJSONKeyEntry([]byte(recipientTemp))
	if err != nil {
		return nil, err
	}
	ssp, err := uid.NewJSONKeyEntry([]byte(senderSessionPub))
	if err != nil {
		return nil, err
	}
	var (
		nssp  *uid.KeyEntry
		nrsps *uid.KeyEntry
	)
	if nextSenderSessionPub != "" {
		nssp, err = uid.NewJSONKeyEntry([]byte(nextSenderSessionPub))
		if err != nil {
			return nil, err
		}
	}
	if nextRecipientSessionPubSeen != "" {
		nrsps, err = uid.NewJSONKeyEntry([]byte(nextRecipientSessionPubSeen))
		if err != nil {
			return nil, err
		}
	}
	ss := &session.State{
		SenderSessionCount:          uint64(senderSessionCount),
		SenderMessageCount:          uint64(senderMessageCount),
		MaxRecipientCount:           uint64(maxRecipientCount),
		RecipientTemp:               *rt,
		SenderSessionPub:            *ssp,
		NextSenderSessionPub:        nssp,
		NextRecipientSessionPubSeen: nrsps,
		NymAddress:                  nymAddress,
	}
	if keyInitSession > 0 {
		ss.KeyInitSession = true
	}
	return ss, nil
}

// SetSessionState adds or updates the given sessionState under
// sessionStateKey in keyDB.
func (keyDB *KeyDB) SetSessionState(
	sessionStateKey string,
	sessionState *session.State,
) error {
	if sessionStateKey == "" {
		return log.Error("keydb: sessionStateKey must be defined")
	}
	if sessionState == nil {
		return log.Error("keydb: sessionState must be defined")
	}
	var (
		nssp  string
		nrsps string
		kis   int64
	)
	if sessionState.NextSenderSessionPub != nil {
		nssp = string(sessionState.NextSenderSessionPub.JSON())
	}
	if sessionState.NextRecipientSessionPubSeen != nil {
		nrsps = string(sessionState.NextRecipientSessionPubSeen.JSON())
	}
	if sessionState.KeyInitSession {
		kis = 1
	}
	res, err :=
		keyDB.updateSessionStateQuery.Exec(sessionState.SenderSessionCount,
			sessionState.SenderMessageCount, sessionState.MaxRecipientCount,
			sessionState.RecipientTemp.JSON(),
			sessionState.SenderSessionPub.JSON(), nssp, nrsps,
			sessionState.NymAddress, kis, sessionStateKey)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := keyDB.insertSessionStateQuery.Exec(sessionStateKey,
			sessionState.SenderSessionCount, sessionState.SenderMessageCount,
			sessionState.MaxRecipientCount, sessionState.RecipientTemp.JSON(),
			sessionState.SenderSessionPub.JSON(), nssp, nrsps,
			sessionState.NymAddress, kis)
		if err != nil {
			return log.Error(err)
		}
	}
	return nil
}
