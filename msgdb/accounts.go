package msgdb

import (
	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
)

// AddAccount adds an account for myID and contactID (which can be nil) with
// given privkey on server.
func (msgDB *MsgDB) AddAccount(
	myID, contactID string,
	privkey *[ed25519.PrivateKeySize]byte,
	server string,
	secret *[64]byte,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
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
	// add account
	_, err := msgDB.addAccountQuery.Exec(mID, cID, base64.Encode(privkey[:]),
		server, base64.Encode(secret[:]), 0, 0)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

// SetAccountTime sets the account time for the given myID and contactID
// combination (contactID can be nil).
func (msgDB *MsgDB) SetAccountTime(
	myID, contactID string,
	loadTime int64,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
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
	// set account time
	if _, err := msgDB.setAccountTimeQuery.Exec(loadTime, mID, cID); err != nil {
		return log.Error(err)
	}
	return nil
}

// SetAccountLastMsg sets the last message time and ID for the given myID and
// contactID combination (contactID can be nil).
func (msgDB *MsgDB) SetAccountLastMsg(
	myID, contactID string,
	lastMessageTime int64,
) error {
	if err := identity.IsMapped(myID); err != nil {
		return log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return log.Error(err)
		}
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
	// set account time
	_, err := msgDB.setAccountLastTimeQuery.Exec(lastMessageTime, mID, cID)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

// GetAccount returns the privkey and server of the account for myID.
func (msgDB *MsgDB) GetAccount(
	myID, contactID string,
) (
	privkey *[ed25519.PrivateKeySize]byte,
	server string,
	secret *[64]byte,
	lastMessageTime int64,
	err error,
) {
	if err := identity.IsMapped(myID); err != nil {
		return nil, "", nil, 0, log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return nil, "", nil, 0, log.Error(err)
		}
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return nil, "", nil, 0, log.Error(err)
	}
	// get ContactID
	var cID int
	if contactID != "" {
		err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID)
		if err != nil {
			return nil, "", nil, 0, log.Error(err)
		}
	}
	// get account data
	var pks string
	var scrts string
	err = msgDB.getAccountQuery.QueryRow(mID, cID).Scan(&pks, &server, &scrts,
		&lastMessageTime)
	if err != nil {
		return nil, "", nil, 0, log.Error(err)
	}
	// decode private key
	pk, err := base64.Decode(pks)
	if err != nil {
		return nil, "", nil, 0, log.Error(err)
	}
	privkey = new([ed25519.PrivateKeySize]byte)
	copy(privkey[:], pk)
	// decode secret
	scrt, err := base64.Decode(scrts)
	if err != nil {
		return nil, "", nil, 0, log.Error(err)
	}
	secret = new([64]byte)
	copy(secret[:], scrt)
	return
}

// GetAccounts returns a list of contactIDs (including nil) of all accounts
// that exist for myID.
func (msgDB *MsgDB) GetAccounts(myID string) ([]string, error) {
	if err := identity.IsMapped(myID); err != nil {
		return nil, log.Error(err)
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return nil, log.Error(err)
	}
	// get contacts
	rows, err := msgDB.getAccountsQuery.Query(mID)
	if err != nil {
		return nil, log.Error(err)
	}
	defer rows.Close()
	var contacts []string
	var cIDs []int64
	for rows.Next() {
		var cID int64
		if err := rows.Scan(&cID); err != nil {
			return nil, log.Error(err)

		}
		if cID == 0 {
			contacts = append(contacts, "")
		} else {
			cIDs = append(cIDs, cID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}
	for _, cID := range cIDs {
		var contact string
		err := msgDB.getContactMappedQuery.QueryRow(mID, cID).Scan(&contact)
		if err != nil {
			return nil, log.Error(err)
		}
		contacts = append(contacts, contact)
	}

	return contacts, nil
}

// GetAccountTime returns the account time for the given myID and contactID
// combination.
func (msgDB *MsgDB) GetAccountTime(
	myID, contactID string,
) (int64, error) {
	if err := identity.IsMapped(myID); err != nil {
		return 0, log.Error(err)
	}
	if contactID != "" {
		if err := identity.IsMapped(contactID); err != nil {
			return 0, log.Error(err)
		}
	}
	// get MyID
	var mID int
	if err := msgDB.getNymUIDQuery.QueryRow(myID).Scan(&mID); err != nil {
		return 0, log.Error(err)
	}
	// get ContactID
	var cID int
	if contactID != "" {
		err := msgDB.getContactUIDQuery.QueryRow(mID, contactID).Scan(&cID)
		if err != nil {
			return 0, log.Error(err)
		}
	}
	// get load time
	var loadTime int64
	err := msgDB.getAccountTimeQuery.QueryRow(mID, cID).Scan(&loadTime)
	if err != nil {
		return 0, err
	}
	return loadTime, nil
}
