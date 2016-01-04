// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package msgdb defines an encrypted database used to store messages.
package msgdb

import (
	"database/sql"

	"github.com/mutecomm/mute/encdb"
)

// Version is the current msgdb version.
const Version = "1"

// Entries in KeyValueTable.
const (
	DBVersion = "Version"   // version string of msgdb
	WalletKey = "WalletKey" // 64-byte private Ed25519 wallet key, base64 encoded
	ActiveUID = "ActiveUID" // the active UID
)

const (
	createQueryKeyValue = `
CREATE TABLE KeyValueStore (
  KeyEntry   TEXT NOT NULL UNIQUE,
  ValueEntry TEXT NOT NULL
);`
	createQueryNyms = `
CREATE TABLE Nyms (
  UID            INTEGER PRIMARY KEY,
  MappedID       TEXT    NOT NULL UNIQUE,
  UnmappedID     TEXT    NOT NULL UNIQUE,
  UpkeepAll      INTEGER NOT NULL DEFAULT 0, -- the last execution of 'upkeep all'
  UpkeepAccounts INTEGER NOT NULL DEFAULT 0, -- the last execution of 'upkeep accounts'
  FullName       TEXT
);`
	/*
	   TODO: add

	   Favorite   INTEGER NOT NULL, -- 0: normal contact, 1: favorite contact
	*/
	createQueryContacts = `
CREATE TABLE Contacts (
  UID        INTEGER PRIMARY KEY,
  MyID       INTEGER NOT NULL,
  MappedID   TEXT NOT NULL,
  UnmappedID TEXT NOT NULL,
  FullName   TEXT,
  Blocked    INTEGER,          -- 0: white list, 1: gray list, 2: black list
  UNIQUE     (MyID, MappedID), -- the combination of nym and contact must be unique
  FOREIGN KEY(MyID) REFERENCES Nyms(UID) ON DELETE CASCADE
);`
	createQueryAccounts = `
CREATE TABLE Accounts (
  AccID       INTEGER PRIMARY KEY, -- the account ID
  MyID        INTEGER NOT NULL,    -- the user ID of this account
  ContactID   INTEGER NOT NULL,    -- optional contact ID of this account (0 == undefined)
  PrivKey     TEXT    NOT NULL,    -- private key of account (Ed25519)
  Server      TEXT    NOT NULL,    -- account server
  Secret      TEXT    NOT NULL,    -- secret used for nym addresses (64 byte random data)
  MinDelay    INTEGER NOT NULL,    -- TODO: is this the best place to store this?
  MaxDelay    INTEGER NOT NULL,    -- TODO: is this the best place to store this?
  LoadTime    INTEGER NOT NULL,    -- time when the account will expire
  LastMsgTime INTEGER NOT NULL,    -- time of the last read message
  UNIQUE     (MyID, ContactID),  -- only one account per pair
  FOREIGN KEY(MyID) REFERENCES Nyms(UID) ON DELETE CASCADE
);`
	/*
	   TODO: add

	   Message-ID  TEXT    NOT NULL, -- a unique message ID for sender (must start with 'nym-')
	   In-Reply-To TEXT,             -- message ID of the message this message is a reply to, if any
	   Archive     INTEGER NOT NULL, -- 1: message is archived
	   Trash       INTEGER NOT NULL, -- 1: message is deleted
	*/
	createQueryMessages = `
CREATE TABLE Messages (
  MsgID       INTEGER PRIMARY KEY,
  Self        INTEGER NOT NULL, -- foreign key to Nyms table
  Peer        INTEGER NOT NULL, -- foreign key to Contacts table
  Direction   INTEGER NOT NULL, -- 0: received message, 1: sent message
  ToSend      INTEGER NOT NULL, -- 1: message still has to be encrypted and added to out queue
  Sent        INTEGER NOT NULL, -- 0: message pending or received message, 1: message has been sent
  "From"      TEXT    NOT NULL, -- sender nym
  "To"        TEXT    NOT NULL, -- comma separated list of recipient nyms (first
                                -- one is 'To:', the optional following ones 'Cc:')
  Date        INTEGER NOT NULL, -- date of the message (not transferred!)
                                -- for sent messages: delivery time to mix + minDelay
                                -- for received messages: time muteaccd received the message
  Subject     TEXT,             -- subject line
  Message     TEXT,             -- message body (with subject line) as cleartext
  Sign        INTEGER NOT NULL, -- permanent signature
  MinDelay    INTEGER NOT NULL, -- minimum delay of message
  MaxDelay    INTEGER NOT NULL, -- maximum delay of message
  Read        INTEGER NOT NULL, -- 0: message is new, 1: message read
  Star        INTEGER NOT NULL,
  FOREIGN KEY(Self) REFERENCES Nyms(UID) ON DELETE CASCADE,
  FOREIGN KEY(Peer) REFERENCES Contacts(UID)
);`
	createQueryAttachments = `
CREATE TABLE Attachments (
  AttachID INTEGER PRIMARY KEY,
  Self     INTEGER NOT NULL, -- foreign key to Nyms table
  Msg      INTEGER NOT NULL, -- foreign key to Messages table
  Filename TEXT    NOT NULL, -- original filename of attachment
  Data     BLOB,             -- the actual attachment data
  Deleted  INTEGER NOT NULL, -- 1: the attachment has been deleted (Data is nil)
  FOREIGN KEY(Self) REFERENCES Nyms(UID) ON DELETE CASCADE,
  FOREIGN KEY(Msg) REFERENCES Messages(MsgID)
);`
	createQueryChunks = `
CREATE TABLE Chunks (
  ChunkID   INTEGER PRIMARY KEY,
  Self      INTEGER NOT NULL, -- foreign key to Nyms table
  MessageID TEXT    NOT NULL, -- message ID of chunk
  Piece     INTEGER NOT NULL, -- piece m of n chunks
  Count     INTEGER NOT NULL, -- total number of chunks (n)
  Date      INTEGER NOT NULL, -- time when the chunk was received from muteaccd
  FOREIGN KEY(Self) REFERENCES Nyms(UID) ON DELETE CASCADE
);`
	createQueryOutQueue = ` 
 CREATE TABLE OutQueue (
  OQIdx      INTEGER PRIMARY KEY,
  Self       INTEGER NOT NULL, -- foreign key to Nyms table
  MsgID      INTEGER NOT NULL, -- message ID of the corresponding plain text message
  Msg        TEXT    NOT NULL, -- encrypted message in the outqueue
  NymAddress TEXT    NOT NULL, -- nymaddress to send message to
  MinDelay   INTEGER NOT NULL, -- minimum delay of message
  MaxDelay   INTEGER NOT NULL, -- maximum delay of message
  Envelope   INTEGER NOT NULL, -- 0: basic encrypted message, 1: with envelope and ready to send
  Resend     INTEGER NOT NULL, -- 0: process message normally, 1: message needs resend
  FOREIGN KEY(Self) REFERENCES Nyms(UID) ON DELETE CASCADE
  FOREIGN KEY(MsgID) REFERENCES Messages(MsgID) ON DELETE CASCADE
);`
	createQueryInQueue = `
CREATE TABLE InQueue (
  IQIdx     INTEGER PRIMARY KEY,
  MyID      INTEGER NOT NULL, -- the user ID of this account
  ContactID INTEGER NOT NULL, -- optional contact ID of this account (0 == undefined)
  Date      INTEGER NOT NULL, -- time when the message was received from muteaccd
  Msg       TEXT    NOT NULL, -- encrypted message in the inqueue
  Envelope  INTEGER NOT NULL, -- 0: basic encrypted message, 1: with envelope (from mix)
  FOREIGN KEY(MyID) REFERENCES Nyms(UID) ON DELETE CASCADE
);`
	createMessageIDCache = `
CREATE TABLE MessageIDCache(
  Entry     INTEGER PRIMARY KEY,
  MyID      INTEGER NOT NULL, -- the user ID of this account
  ContactID INTEGER NOT NULL, -- optional contact ID of this account (0 == undefined)
  MessageID TEXT    NOT NULL, -- server messageID (from muteaccd)
  FOREIGN KEY(MyID) REFERENCES Nyms(UID) ON DELETE CASCADE
);`
	updateValueQuery            = "UPDATE KeyValueStore SET ValueEntry=? WHERE KeyEntry=?;"
	insertValueQuery            = "INSERT INTO KeyValueStore (KeyEntry, ValueEntry) VALUES (?, ?);"
	getValueQuery               = "SELECT ValueEntry FROM KeyValueStore WHERE KeyEntry=?;"
	updateNymQuery              = "UPDATE Nyms SET UnmappedID=?, FullName=? WHERE MappedID=?;"
	insertNymQuery              = "INSERT INTO Nyms (MappedID, UnmappedID, FullName) VALUES (?, ?, ?);"
	getNymQuery                 = "SELECT UnmappedID, FullName from Nyms WHERE MappedID=?;"
	getNymMappedQuery           = "SELECT MappedID FROM Nyms WHERE UID=?"
	getNymUIDQuery              = "SELECT UID from Nyms WHERE MappedID=?;"
	getNymsQuery                = "SELECT MappedID, UnmappedID, FullName from Nyms;"
	delNymQuery                 = "DELETE FROM Nyms WHERE MappedID=?;"
	getContactQuery             = "SELECT UnmappedID, FullName, Blocked FROM Contacts WHERE MyID=? AND MappedID=?;"
	getContactMappedQuery       = "SELECT MappedID FROM Contacts WHERE MyID=? AND UID=?;"
	getContactUIDQuery          = "SELECT UID FROM Contacts WHERE MyID=? AND MappedID=?;"
	getContactsQuery            = "SELECT UnmappedID, FullName FROM Contacts WHERE MyID=? AND Blocked=?;"
	updateContactQuery          = "UPDATE Contacts SET UnmappedID=?, FullName=?, Blocked=? WHERE MyID=? AND MappedID=?;"
	insertContactQuery          = "INSERT INTO Contacts (MyID, MappedID, UnmappedID, FullName, Blocked) VALUES (?, ?, ?, ?, ?);"
	delContactQuery             = "UPDATE Contacts SET Blocked=1 WHERE MyID=? AND MappedID=?;"
	addAccountQuery             = "INSERT INTO Accounts (MyID, ContactID, PrivKey, Server, Secret, MinDelay, MaxDelay, LoadTime, LastMsgTime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
	setAccountTimeQuery         = "UPDATE Accounts SET LoadTime=? WHERE MyID=? AND ContactID=?;"
	setAccountLastTimeQuery     = "UPDATE Accounts SET LastMsgTime=? WHERE MyID=? AND ContactID=?;"
	getAccountQuery             = "SELECT PrivKey, Server, Secret, MinDelay, MaxDelay, LastMsgTime FROM Accounts WHERE MyID=? AND ContactID=?;"
	getAccountsQuery            = "SELECT ContactID FROM Accounts WHERE MyID=?;"
	getAccountTimeQuery         = "SELECT LoadTime FROM Accounts WHERE MyID=? AND ContactID=?;"
	addMsgQuery                 = "INSERT INTO Messages (Self, Peer, Direction, ToSend, Sent, \"From\", \"To\", Date, Subject, Message, Sign, MinDelay, MaxDelay, Read, Star) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0);"
	delMsgQuery                 = "DELETE FROM Messages WHERE MsgID=? AND Self=?;"
	getMsgQuery                 = "SELECT Self, Peer, Direction, Message FROM Messages WHERE MsgID=?;"
	readMsgQuery                = "UPDATE Messages SET Read=1 WHERE MsgID=?;"
	getMsgsQuery                = "SELECT MsgID, \"From\", \"To\", Direction, Sent, Date, Subject, Read FROM Messages WHERE Self=?;"
	getUndeliveredMsgQuery      = "SELECT MsgID, Peer, Message, Sign, MinDelay, MaxDelay FROM Messages WHERE Self=? AND ToSend=1 ORDER BY MsgID ASC LIMIT 1;"
	updateDeliveryMsgQuery      = "UPDATE Messages SET ToSend=? WHERE MsgID=?;"
	updateMsgDateQuery          = "UPDATE Messages SET Date=?, Sent=1 WHERE MsgID=?;"
	getUpkeepAllQuery           = "SELECT UpkeepAll FROM Nyms WHERE MappedID=?;"
	setUpkeepAllQuery           = "UPDATE Nyms SET UpkeepAll=? WHERE MappedID=?;"
	getUpkeepAccountsQuery      = "SELECT UpkeepAccounts FROM Nyms WHERE MappedID=?;"
	setUpkeepAccountsQuery      = "UPDATE Nyms SET UpkeepAccounts=? WHERE MappedID=?;"
	addOutQueueQuery            = "INSERT INTO OutQueue (Self, MsgID, Msg, NymAddress, MinDelay, MaxDelay, Envelope, Resend) VALUES (?, ?, ?, ?, ?, ?, 0, 0);"
	getOutQueueQuery            = "SELECT OQIdx, Msg, NymAddress, MinDelay, MaxDelay, Envelope FROM OutQueue WHERE Self=? AND Resend=0 ORDER BY OQIdx ASC LIMIT 1;"
	getOutQueueMsgIDQuery       = "SELECT MsgID FROM OutQueue WHERE OQIdx=?;"
	setOutQueueQuery            = "UPDATE OutQueue SET Msg=?, Envelope=1 WHERE OQIdx=?;"
	removeOutQueueQuery         = "DELETE FROM OutQueue WHERE OQIdx=?;"
	setResendOutQueueQuery      = "UPDATE OutQueue SET Resend=1 WHERE OQIdx=?;"
	clearResendOutQueueQuery    = "UPDATE OutQueue SET Resend=0 WHERE Self=? AND Resend=1;"
	addInQueueQuery             = "INSERT INTO InQueue (MyID, ContactID, Date, Msg, Envelope) VALUES (?, ?, ?, ?, 1);"
	getInQueueQuery             = "SELECT IQIdx, MyID, ContactID, Msg, Envelope FROM InQueue ORDER BY IQIdx ASC LIMIT 1;"
	getInQueueIDsQuery          = "SELECT MyID, ContactID, Date FROM InQueue WHERE IQIdx=?;"
	setInQueueQuery             = "UPDATE InQueue SET Msg=?, Envelope=0 WHERE IQIdx=?;"
	removeInQueueQuery          = "DELETE FROM InQueue WHERE IQIdx=?;"
	addMessageIDCacheQuery      = "INSERT INTO MessageIDCache (MyID, ContactID, MessageID) VALUES (?, ?, ?);"
	getMessageIDCacheQuery      = "SELECT MessageID FROM MessageIDCache WHERE MyID=? AND ContactID=?;"
	getMessageIDCacheEntryQuery = "SELECT Entry FROM MessageIDCache WHERE MyID=? AND ContactID=? AND MessageID=?;"
	removeMessageIDCacheQuery   = "DELETE FROM MessageIDCache WHERE MyID=? AND ContactID=? AND Entry<?;"
)

// MsgDB is a handle for an encrypted database to store messsages and tokens.
type MsgDB struct {
	encDB                       *sql.DB
	updateValueQuery            *sql.Stmt
	insertValueQuery            *sql.Stmt
	getValueQuery               *sql.Stmt
	updateNymQuery              *sql.Stmt
	insertNymQuery              *sql.Stmt
	getNymQuery                 *sql.Stmt
	getNymMappedQuery           *sql.Stmt
	getNymUIDQuery              *sql.Stmt
	getNymsQuery                *sql.Stmt
	delNymQuery                 *sql.Stmt
	getContactQuery             *sql.Stmt
	getContactMappedQuery       *sql.Stmt
	getContactUIDQuery          *sql.Stmt
	getContactsQuery            *sql.Stmt
	updateContactQuery          *sql.Stmt
	insertContactQuery          *sql.Stmt
	delContactQuery             *sql.Stmt
	addAccountQuery             *sql.Stmt
	setAccountTimeQuery         *sql.Stmt
	setAccountLastTimeQuery     *sql.Stmt
	getAccountQuery             *sql.Stmt
	getAccountsQuery            *sql.Stmt
	getAccountTimeQuery         *sql.Stmt
	addMsgQuery                 *sql.Stmt
	delMsgQuery                 *sql.Stmt
	getMsgQuery                 *sql.Stmt
	readMsgQuery                *sql.Stmt
	getMsgsQuery                *sql.Stmt
	getUndeliveredMsgQuery      *sql.Stmt
	updateDeliveryMsgQuery      *sql.Stmt
	updateMsgDateQuery          *sql.Stmt
	getUpkeepAllQuery           *sql.Stmt
	setUpkeepAllQuery           *sql.Stmt
	getUpkeepAccountsQuery      *sql.Stmt
	setUpkeepAccountsQuery      *sql.Stmt
	addOutQueueQuery            *sql.Stmt
	getOutQueueQuery            *sql.Stmt
	getOutQueueMsgIDQuery       *sql.Stmt
	setOutQueueQuery            *sql.Stmt
	removeOutQueueQuery         *sql.Stmt
	setResendOutQueueQuery      *sql.Stmt
	clearResendOutQueueQuery    *sql.Stmt
	addInQueueQuery             *sql.Stmt
	getInQueueQuery             *sql.Stmt
	getInQueueIDsQuery          *sql.Stmt
	setInQueueQuery             *sql.Stmt
	removeInQueueQuery          *sql.Stmt
	addMessageIDCacheQuery      *sql.Stmt
	getMessageIDCacheQuery      *sql.Stmt
	getMessageIDCacheEntryQuery *sql.Stmt
	removeMessageIDCacheQuery   *sql.Stmt
}

// Create returns a new message database with the given dbname.
// It is encrypted by passphrase (processed by a KDF with iter many iterations).
func Create(dbname string, passphrase []byte, iter int) error {
	err := encdb.Create(dbname, passphrase, iter, []string{
		createQueryKeyValue,
		createQueryNyms,
		createQueryContacts,
		createQueryAccounts,
		createQueryMessages,
		createQueryAttachments,
		createQueryChunks,
		createQueryOutQueue,
		createQueryInQueue,
		createMessageIDCache,
	})
	if err != nil {
		return err
	}
	msgDB, err := Open(dbname, passphrase)
	if err != nil {
		return err
	}
	defer msgDB.Close()
	if err := msgDB.AddValue(DBVersion, Version); err != nil {
		return err
	}
	return nil
}

// Version returns the current version of msgDB.
func (msgDB *MsgDB) Version() (string, error) {
	version, err := msgDB.GetValue(DBVersion)
	if err != nil {
		return "", err
	}
	return version, nil
}

// Open opens the message database with dbname and passphrase.
func Open(dbname string, passphrase []byte) (*MsgDB, error) {
	var msgDB MsgDB
	var err error
	msgDB.encDB, err = encdb.Open(dbname, passphrase)
	if err != nil {
		return nil, err
	}
	if msgDB.updateValueQuery, err = msgDB.encDB.Prepare(updateValueQuery); err != nil {
		return nil, err
	}
	if msgDB.insertValueQuery, err = msgDB.encDB.Prepare(insertValueQuery); err != nil {
		return nil, err
	}
	if msgDB.getValueQuery, err = msgDB.encDB.Prepare(getValueQuery); err != nil {
		return nil, err
	}
	if msgDB.updateNymQuery, err = msgDB.encDB.Prepare(updateNymQuery); err != nil {
		return nil, err
	}
	if msgDB.insertNymQuery, err = msgDB.encDB.Prepare(insertNymQuery); err != nil {
		return nil, err
	}
	if msgDB.getNymQuery, err = msgDB.encDB.Prepare(getNymQuery); err != nil {
		return nil, err
	}
	if msgDB.getNymMappedQuery, err = msgDB.encDB.Prepare(getNymMappedQuery); err != nil {
		return nil, err
	}
	if msgDB.getNymUIDQuery, err = msgDB.encDB.Prepare(getNymUIDQuery); err != nil {
		return nil, err
	}
	if msgDB.getNymsQuery, err = msgDB.encDB.Prepare(getNymsQuery); err != nil {
		return nil, err
	}
	if msgDB.delNymQuery, err = msgDB.encDB.Prepare(delNymQuery); err != nil {
		return nil, err
	}
	if msgDB.getContactQuery, err = msgDB.encDB.Prepare(getContactQuery); err != nil {
		return nil, err
	}
	if msgDB.getContactMappedQuery, err = msgDB.encDB.Prepare(getContactMappedQuery); err != nil {
		return nil, err
	}
	if msgDB.getContactUIDQuery, err = msgDB.encDB.Prepare(getContactUIDQuery); err != nil {
		return nil, err
	}
	if msgDB.getContactsQuery, err = msgDB.encDB.Prepare(getContactsQuery); err != nil {
		return nil, err
	}
	if msgDB.updateContactQuery, err = msgDB.encDB.Prepare(updateContactQuery); err != nil {
		return nil, err
	}
	if msgDB.insertContactQuery, err = msgDB.encDB.Prepare(insertContactQuery); err != nil {
		return nil, err
	}
	if msgDB.delContactQuery, err = msgDB.encDB.Prepare(delContactQuery); err != nil {
		return nil, err
	}
	if msgDB.addAccountQuery, err = msgDB.encDB.Prepare(addAccountQuery); err != nil {
		return nil, err
	}
	if msgDB.setAccountTimeQuery, err = msgDB.encDB.Prepare(setAccountTimeQuery); err != nil {
		return nil, err
	}
	if msgDB.setAccountLastTimeQuery, err = msgDB.encDB.Prepare(setAccountLastTimeQuery); err != nil {
		return nil, err
	}
	if msgDB.getAccountQuery, err = msgDB.encDB.Prepare(getAccountQuery); err != nil {
		return nil, err
	}
	if msgDB.getAccountsQuery, err = msgDB.encDB.Prepare(getAccountsQuery); err != nil {
		return nil, err
	}
	if msgDB.getAccountTimeQuery, err = msgDB.encDB.Prepare(getAccountTimeQuery); err != nil {
		return nil, err
	}
	if msgDB.addMsgQuery, err = msgDB.encDB.Prepare(addMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.delMsgQuery, err = msgDB.encDB.Prepare(delMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.getMsgQuery, err = msgDB.encDB.Prepare(getMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.readMsgQuery, err = msgDB.encDB.Prepare(readMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.getMsgsQuery, err = msgDB.encDB.Prepare(getMsgsQuery); err != nil {
		return nil, err
	}
	if msgDB.getUndeliveredMsgQuery, err = msgDB.encDB.Prepare(getUndeliveredMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.updateDeliveryMsgQuery, err = msgDB.encDB.Prepare(updateDeliveryMsgQuery); err != nil {
		return nil, err
	}
	if msgDB.updateMsgDateQuery, err = msgDB.encDB.Prepare(updateMsgDateQuery); err != nil {
		return nil, err
	}
	if msgDB.getUpkeepAllQuery, err = msgDB.encDB.Prepare(getUpkeepAllQuery); err != nil {
		return nil, err
	}
	if msgDB.setUpkeepAllQuery, err = msgDB.encDB.Prepare(setUpkeepAllQuery); err != nil {
		return nil, err
	}
	if msgDB.getUpkeepAccountsQuery, err = msgDB.encDB.Prepare(getUpkeepAccountsQuery); err != nil {
		return nil, err
	}
	if msgDB.setUpkeepAccountsQuery, err = msgDB.encDB.Prepare(setUpkeepAccountsQuery); err != nil {
		return nil, err
	}
	if msgDB.addOutQueueQuery, err = msgDB.encDB.Prepare(addOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.getOutQueueQuery, err = msgDB.encDB.Prepare(getOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.getOutQueueMsgIDQuery, err = msgDB.encDB.Prepare(getOutQueueMsgIDQuery); err != nil {
		return nil, err
	}
	if msgDB.setOutQueueQuery, err = msgDB.encDB.Prepare(setOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.removeOutQueueQuery, err = msgDB.encDB.Prepare(removeOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.setResendOutQueueQuery, err = msgDB.encDB.Prepare(setResendOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.clearResendOutQueueQuery, err = msgDB.encDB.Prepare(clearResendOutQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.addInQueueQuery, err = msgDB.encDB.Prepare(addInQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.getInQueueQuery, err = msgDB.encDB.Prepare(getInQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.getInQueueIDsQuery, err = msgDB.encDB.Prepare(getInQueueIDsQuery); err != nil {
		return nil, err
	}
	if msgDB.setInQueueQuery, err = msgDB.encDB.Prepare(setInQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.removeInQueueQuery, err = msgDB.encDB.Prepare(removeInQueueQuery); err != nil {
		return nil, err
	}
	if msgDB.addMessageIDCacheQuery, err = msgDB.encDB.Prepare(addMessageIDCacheQuery); err != nil {
		return nil, err
	}
	if msgDB.getMessageIDCacheQuery, err = msgDB.encDB.Prepare(getMessageIDCacheQuery); err != nil {
		return nil, err
	}
	if msgDB.getMessageIDCacheEntryQuery, err = msgDB.encDB.Prepare(getMessageIDCacheEntryQuery); err != nil {
		return nil, err
	}
	if msgDB.removeMessageIDCacheQuery, err = msgDB.encDB.Prepare(removeMessageIDCacheQuery); err != nil {
		return nil, err
	}
	return &msgDB, nil
}

// DB returns the internal database handle for message database.
// Usually this method should not be used!
func (msgDB *MsgDB) DB() *sql.DB {
	return msgDB.encDB
}

// Close the message database.
func (msgDB *MsgDB) Close() error {
	return msgDB.encDB.Close()
}

// Rekey tries to rekey the message database dbname with the newPassphrase
// (processed by a KDF with iter many iterations). The supplied oldPassphrase
// must be correct, otherwise an error is returned.
func Rekey(dbname string, oldPassphrase, newPassphrase []byte, newIter int) error {
	return encdb.Rekey(dbname, oldPassphrase, newPassphrase, newIter)
}

// Status returns the autoVacuum mode and freelistCount of msgDB.
func (msgDB *MsgDB) Status() (
	autoVacuum string,
	freelistCount int64,
	err error,
) {
	return encdb.Status(msgDB.encDB)
}

// Vacuum executes VACUUM command in msgDB. If autoVacuumMode is not nil and
// different from the current one, the auto_vacuum mode is changed before
// VACUUM is executed.
func (msgDB *MsgDB) Vacuum(autoVacuumMode string) error {
	return encdb.Vacuum(msgDB.encDB, autoVacuumMode)
}

// Incremental executes incremental_vacuum to free up to pages many pages. If
// pages is 0, all pages are freed. If the current auto_vacuum mode is not
// INCREMENTAL, an error is returned.
func (msgDB *MsgDB) Incremental(pages int64) error {
	return encdb.Incremental(msgDB.encDB, pages)
}
