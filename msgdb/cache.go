package msgdb

import (
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddMessageIDCache adds messageID to the message ID cache for the myID and
// contactID pair.
func (msgDB *MsgDB) AddMessageIDCache(myID, contactID, messageID string) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
	}
	if messageID == "" {
		return log.Error(ErrNilMessageID)
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return log.Error(err)
	}
	// get ContactID
	var cID int
	if contactID != "" {
		err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID)
		if err != nil {
			return log.Error(err)
		}
	}
	// add messageID to cache
	_, err := msgDB.addMessageIDCacheQuery.Exec(mID, cID, messageID)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

// GetMessageIDCache retursn the message ID cache for the myID and contactID
// pair.
func (msgDB *MsgDB) GetMessageIDCache(myID, contactID string) (
	map[string]bool,
	error,
) {
	if err := identity.IsMapped(myID); err != nil {
		return nil, log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return nil, log.Error(err)
		}
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return nil, log.Error(err)
	}
	// get ContactID
	var cID int
	if contactID != "" {
		err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID)
		if err != nil {
			return nil, log.Error(err)
		}
	}
	// get cache
	rows, err := msgDB.getMessageIDCacheQuery.Query(mID, cID)
	if err != nil {
		return nil, log.Error(err)
	}
	cache := make(map[string]bool)
	defer rows.Close()
	for rows.Next() {
		var messageID string
		if err := rows.Scan(&messageID); err != nil {
			return nil, log.Error(err)
		}
		cache[messageID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}

	return cache, nil
}

// RemoveMessageIDCache removes all entries from the message ID cache for the
// myID and contactID pair which are older than messageID.
func (msgDB *MsgDB) RemoveMessageIDCache(
	myID, contactID, messageID string,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
	}
	if messageID == "" {
		return log.Error(ErrNilMessageID)
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return log.Error(err)
	}
	// get ContactID
	var cID int
	if contactID != "" {
		err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID)
		if err != nil {
			return log.Error(err)
		}
	}
	// get entry for given messageID
	var entry int64
	err := msgDB.getMessageIDCacheEntryQuery.QueryRow(mID, cID, messageID).Scan(&entry)
	if err != nil {
		return log.Error(err)
	}
	// remove all entries older than messageID
	_, err = msgDB.removeMessageIDCacheQuery.Exec(mID, cID, entry)
	if err != nil {
		return log.Error(err)
	}
	return nil
}
