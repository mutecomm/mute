// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keydb defines an encrypted database used to store cryptographic
// keys.
package keydb

import (
	"database/sql"

	"github.com/mutecomm/mute/encdb"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
)

// Version is the current keydb version.
const Version = "1"

// Entries in KeyValueTable.
const (
	DBVersion = "Version" // version string of keydb
)

const (
	createQueryKeyValue = `
  CREATE TABLE KeyValueStore (
    KeyEntry   TEXT NOT NULL UNIQUE,
    ValueEntry TEXT NOT NULL
);`
	createQueryPrivateUIDs = `
CREATE TABLE PrivateUIDs (
  ID              INTEGER PRIMARY KEY,
  IDENTITY        TEXT    NOT NULL,
  MSGCOUNT        INTEGER NOT NULL,
  UIDMessage      TEXT    NOT NULL,
  SIGPRIVKEY      TEXT    NOT NULL,
  ENCPRIVKEY      TEXT    NOT NULL,
  UIDMessageReply TEXT
);`
	createQueryPublicUIDs = `
CREATE TABLE PublicUIDs (
  ID         INTEGER PRIMARY KEY,
  IDENTITY   TEXT    NOT NULL,
  MSGCOUNT   INTEGER NOT NULL,
  POSITION   INTEGER NOT NULL,
  UIDMessage TEXT    NOT NULL
);`
	createQueryPrivateKeyInits = `
CREATE TABLE PrivateKeyInits (
  ID              INTEGER PRIMARY KEY,
  SIGKEYHASH      TEXT    NOT NULL,
  PUBKEYHASH      TEXT    NOT NULL,
  KeyInit         TEXT    NOT NULL,
  SigPubKey       TEXT    NOT NULL,
  PRIVKEY         TEXT    NOT NULL,
  ServerSignature TEXT    NOT NULL
);`
	createQueryPublicKeyInits = `
CREATE TABLE PublicKeyInits (
  ID         INTEGER PRIMARY KEY,
  SIGKEYHASH TEXT    NOT NULL,
  KeyInit    TEXT    NOT NULL
 );`
	createQuerySessions = `
CREATE TABLE Sessions (
  SessionID   INTEGER PRIMARY KEY,
  SessionKey  TEXT    NOT NULL,
  RootKeyHash TEXT    NOT NULL,
  ChainKey    TEXT    NOT NULL,
  NumOfKeys   INTEGER NOT NULL
);`
	createQueryMessageKeys = `
CREATE TABLE MessageKeys (
  ID        INTEGER PRIMARY KEY,
  SessionID INTEGER NOT NULL,
  Number    INTEGER NOT NULL, -- the key number
  Key       TEXT    NOT NULL, -- the actual key (JSON encoded)
  Direction INTEGER NOT NULL  -- 1: sender key, 0: receiver key
  -- TODO: fix this:
  -- FOREIGN KEY(SessionID) REFERENCES Sessions(SessionID) ON DELETE CASCADE
);`
	createQueryHashchains = `
CREATE TABLE Hashchains (
  ID       INTEGER PRIMARY KEY,
  Domain   TEXT    NOT NULL,
  Position INTEGER NOT NULL,
  Entry    TEXT    NOT NULL
);`
	createQuerySessionStates = `
CREATE TABLE SessionStates (
  ID                          INTEGER PRIMARY KEY,
  SessionStateKey             TEXT    NOT NULL,
  SenderSessionCount          INTEGER NOT NULL,
  SenderMessageCount          INTEGER NOT NULL,
  MaxRecipientCount           INTEGER NOT NULL,
  RecipientTemp               TEXT    NOT NULL,
  SenderSessionPub            TEXT    NOT NULL,
  NextSenderSessionPub        TEXT,
  NextRecipientSessionPubSeen TEXT,
  NymAddress                  TEXT    NOT NULL,
  KeyInitSession              INTEGER NOT NULL
);`
	createQuerySessionKeys = `
CREATE TABLE SessionKeys (
  ID          INTEGER PRIMARY KEY,
  Hash        TEXT    NOT NULL,
  Json        TEXT    NOT NULL,
  PrivKey     TEXT,
  CleanupTime INTEGER NOT NULL
);`
	updateValueQuery          = "UPDATE KeyValueStore SET ValueEntry=? WHERE KeyEntry=?;"
	insertValueQuery          = "INSERT INTO KeyValueStore (KeyEntry, ValueEntry) VALUES (?, ?);"
	getValueQuery             = "SELECT ValueEntry FROM KeyValueStore WHERE KeyEntry=?;"
	addPrivateUIDQuery        = "INSERT INTO PrivateUIDs (IDENTITY, MSGCOUNT, UIDMessage, SIGPRIVKEY, ENCPRIVKEY, UIDMessageReply) VALUES (?, ?, ?, ?, ?, ?);"
	addPrivateUIDReplyQuery   = "UPDATE PrivateUIDs SET UIDMessageReply=? WHERE UIDMessage=?;"
	delPrivateUIDQuery        = "DELETE FROM PrivateUIDs WHERE UIDMessage=?;"
	getPrivateIdentitiesQuery = "SELECT DISTINCT IDENTITY FROM PrivateUIDs;"
	getPrivateUIDQuery        = "SELECT UIDMessage, SIGPRIVKEY, ENCPRIVKEY, UIDMessageReply FROM PrivateUIDs WHERE IDENTITY=? ORDER BY MSGCOUNT DESC;"
	addPrivateKeyInitQuery    = "INSERT INTO PrivateKeyInits (SIGKEYHASH, PUBKEYHASH, KeyInit, SigPubKey, PRIVKEY, ServerSignature) VALUES (?, ?, ?, ?, ?, ?);"
	getPrivateKeyInitQuery    = "SELECT KeyInit, SigPubKey, PRIVKEY FROM PrivateKeyInits WHERE PUBKEYHASH=?;"
	addPublicKeyInitQuery     = "INSERT INTO PublicKeyInits (SIGKEYHASH, KeyInit) VALUES (?, ?);"
	getPublicKeyInitQuery     = "SELECT KeyInit FROM PublicKeyInits WHERE SIGKEYHASH=?;"
	addPublicUIDQuery         = "INSERT INTO PublicUIDs (IDENTITY, MSGCOUNT, POSITION, UIDMessage) VALUES (?, ?, ?, ?);"
	getPublicUIDQuery         = "SELECT UIDMessage, POSITION FROM PublicUIDs WHERE IDENTITY=? and POSITION<=? ORDER BY POSITION DESC;"
	getSessionQuery           = "SELECT RootKeyHash, ChainKey, NumOfKeys FROM Sessions WHERE SessionKey=?;"
	getSessionIDQuery         = "SELECT SessionID FROM Sessions WHERE SessionKey=?;"
	updateSessionQuery        = "UPDATE Sessions SET ChainKey=?, NumOfKeys=? WHERE SessionKey=?;"
	insertSessionQuery        = "INSERT INTO Sessions(SessionKey, RootKeyHash, ChainKey, NumOfKeys) VALUES (?, ?, ?, ?);"
	addMessageKeyQuery        = "INSERT INTO MessageKeys(SessionID, Number, Key, Direction) VALUES (?, ?, ?, ?);"
	delMessageKeyQuery        = "DELETE FROM MessageKeys WHERE SessionID=? AND Number=? AND Direction=?;"
	getMessageKeyQuery        = "SELECT Key FROM MessageKeys WHERE SessionID=? AND Number=? AND Direction=?;"
	addHashChainEntryQuery    = "INSERT INTO Hashchains(Domain, Position, Entry) VALUES (?, ?, ?);"
	getHashChainEntryQuery    = "SELECT Entry FROM Hashchains WHERE Domain=? AND Position=?;"
	getLastHashChainPosQuery  = "SELECT Position FROM Hashchains WHERE Domain=? ORDER BY Position DESC;"
	delHashChainQuery         = "DELETE FROM Hashchains WHERE Domain=?;"
	updateSessionStateQuery   = "UPDATE SessionStates SET SenderSessionCount=?, SenderMessageCount=?, " +
		"MaxRecipientCount=?, RecipientTemp=?, SenderSessionPub=?, NextSenderSessionPub=?, " +
		"NextRecipientSessionPubSeen=?, NymAddress=?, KeyInitSession=? WHERE SessionStateKey=?;"
	insertSessionStateQuery = "INSERT INTO SessionStates (SessionStateKey, SenderSessionCount, " +
		"SenderMessageCount, MaxRecipientCount, RecipientTemp, SenderSessionPub, " +
		"NextSenderSessionPub, NextRecipientSessionPubSeen, NymAddress, KeyInitSession) VALUES " +
		"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
	getSessionStateQuery = "SELECT SenderSessionCount, SenderMessageCount, MaxRecipientCount, " +
		"RecipientTemp, SenderSessionPub, NextSenderSessionPub, NextRecipientSessionPubSeen, " +
		"NymAddress, KeyInitSession FROM SessionStates WHERE SessionStateKey=?;"
	updateSessionKeyQuery = "UPDATE SessionKeys SET PrivKey=? WHERE Hash=?;"
	insertSessionKeyQuery = "INSERT INTO SessionKeys (Hash, Json, PrivKey, CleanupTime) VALUES (?, ?, ?, ?);"
	getSessionKeyQuery    = "SELECT Json, PrivKey FROM SessionKeys WHERE Hash=?;"
)

// KeyDB is a handle for an encrypted database used to store mute keys.
type KeyDB struct {
	encDB                     *sql.DB // handle for encDB
	updateValueQuery          *sql.Stmt
	insertValueQuery          *sql.Stmt
	getValueQuery             *sql.Stmt
	addPrivateUIDQuery        *sql.Stmt
	addPrivateUIDReplyQuery   *sql.Stmt
	delPrivateUIDQuery        *sql.Stmt
	getPrivateIdentitiesQuery *sql.Stmt
	getPrivateUIDQuery        *sql.Stmt
	addPrivateKeyInitQuery    *sql.Stmt
	getPrivateKeyInitQuery    *sql.Stmt
	addPublicKeyInitQuery     *sql.Stmt
	getPublicKeyInitQuery     *sql.Stmt
	addPublicUIDQuery         *sql.Stmt
	getPublicUIDQuery         *sql.Stmt
	getSessionQuery           *sql.Stmt
	getSessionIDQuery         *sql.Stmt
	updateSessionQuery        *sql.Stmt
	insertSessionQuery        *sql.Stmt
	addMessageKeyQuery        *sql.Stmt
	delMessageKeyQuery        *sql.Stmt
	getMessageKeyQuery        *sql.Stmt
	addHashChainEntryQuery    *sql.Stmt
	getHashChainEntryQuery    *sql.Stmt
	getLastHashChainPosQuery  *sql.Stmt
	delHashChainQuery         *sql.Stmt
	updateSessionStateQuery   *sql.Stmt
	insertSessionStateQuery   *sql.Stmt
	getSessionStateQuery      *sql.Stmt
	updateSessionKeyQuery     *sql.Stmt
	insertSessionKeyQuery     *sql.Stmt
	getSessionKeyQuery        *sql.Stmt
}

// Create returns a new KEY database with the given dbname.
// It is encrypted by passphrase (processed by a KDF with iter many iterations).
func Create(dbname string, passphrase []byte, iter int) error {
	err := encdb.Create(dbname, passphrase, iter, []string{
		createQueryKeyValue,
		createQueryPrivateUIDs,
		createQueryPublicUIDs,
		createQueryPrivateKeyInits,
		createQueryPublicKeyInits,
		createQuerySessions,
		createQueryMessageKeys,
		createQueryHashchains,
		createQuerySessionStates,
		createQuerySessionKeys,
	})
	if err != nil {
		return err
	}
	keyDB, err := Open(dbname, passphrase)
	if err != nil {
		return err
	}
	defer keyDB.Close()
	if err := keyDB.AddValue(DBVersion, Version); err != nil {
		return err
	}
	return nil
}

// Version returns the current version of keyDB.
func (keyDB *KeyDB) Version() (string, error) {
	version, err := keyDB.GetValue(DBVersion)
	if err != nil {
		return "", err
	}
	return version, nil
}

// Open opens the key database with dbname and passphrase.
func Open(dbname string, passphrase []byte) (*KeyDB, error) {
	var keyDB KeyDB
	var err error
	keyDB.encDB, err = encdb.Open(dbname, passphrase)
	if err != nil {
		return nil, err
	}
	if keyDB.updateValueQuery, err = keyDB.encDB.Prepare(updateValueQuery); err != nil {
		return nil, err
	}
	if keyDB.insertValueQuery, err = keyDB.encDB.Prepare(insertValueQuery); err != nil {
		return nil, err
	}
	if keyDB.getValueQuery, err = keyDB.encDB.Prepare(getValueQuery); err != nil {
		return nil, err
	}
	if keyDB.addPrivateUIDQuery, err = keyDB.encDB.Prepare(addPrivateUIDQuery); err != nil {
		return nil, err
	}
	if keyDB.addPrivateUIDReplyQuery, err = keyDB.encDB.Prepare(addPrivateUIDReplyQuery); err != nil {
		return nil, err
	}
	if keyDB.delPrivateUIDQuery, err = keyDB.encDB.Prepare(delPrivateUIDQuery); err != nil {
		return nil, err
	}
	if keyDB.getPrivateIdentitiesQuery, err = keyDB.encDB.Prepare(getPrivateIdentitiesQuery); err != nil {
		return nil, err
	}
	if keyDB.getPrivateUIDQuery, err = keyDB.encDB.Prepare(getPrivateUIDQuery); err != nil {
		return nil, err
	}
	if keyDB.addPrivateKeyInitQuery, err = keyDB.encDB.Prepare(addPrivateKeyInitQuery); err != nil {
		return nil, err
	}
	if keyDB.getPrivateKeyInitQuery, err = keyDB.encDB.Prepare(getPrivateKeyInitQuery); err != nil {
		return nil, err
	}
	if keyDB.addPublicKeyInitQuery, err = keyDB.encDB.Prepare(addPublicKeyInitQuery); err != nil {
		return nil, err
	}
	if keyDB.getPublicKeyInitQuery, err = keyDB.encDB.Prepare(getPublicKeyInitQuery); err != nil {
		return nil, err
	}
	if keyDB.addPublicUIDQuery, err = keyDB.encDB.Prepare(addPublicUIDQuery); err != nil {
		return nil, err
	}
	if keyDB.getPublicUIDQuery, err = keyDB.encDB.Prepare(getPublicUIDQuery); err != nil {
		return nil, err
	}
	if keyDB.getSessionQuery, err = keyDB.encDB.Prepare(getSessionQuery); err != nil {
		return nil, err
	}
	if keyDB.getSessionIDQuery, err = keyDB.encDB.Prepare(getSessionIDQuery); err != nil {
		return nil, err
	}
	if keyDB.updateSessionQuery, err = keyDB.encDB.Prepare(updateSessionQuery); err != nil {
		return nil, err
	}
	if keyDB.insertSessionQuery, err = keyDB.encDB.Prepare(insertSessionQuery); err != nil {
		return nil, err
	}
	if keyDB.addMessageKeyQuery, err = keyDB.encDB.Prepare(addMessageKeyQuery); err != nil {
		return nil, err
	}
	if keyDB.delMessageKeyQuery, err = keyDB.encDB.Prepare(delMessageKeyQuery); err != nil {
		return nil, err
	}
	if keyDB.getMessageKeyQuery, err = keyDB.encDB.Prepare(getMessageKeyQuery); err != nil {
		return nil, err
	}
	if keyDB.addHashChainEntryQuery, err = keyDB.encDB.Prepare(addHashChainEntryQuery); err != nil {
		return nil, err
	}
	if keyDB.getHashChainEntryQuery, err = keyDB.encDB.Prepare(getHashChainEntryQuery); err != nil {
		return nil, err
	}
	if keyDB.getLastHashChainPosQuery, err = keyDB.encDB.Prepare(getLastHashChainPosQuery); err != nil {
		return nil, err
	}
	if keyDB.delHashChainQuery, err = keyDB.encDB.Prepare(delHashChainQuery); err != nil {
		return nil, err
	}
	if keyDB.updateSessionStateQuery, err = keyDB.encDB.Prepare(updateSessionStateQuery); err != nil {
		return nil, err
	}
	if keyDB.insertSessionStateQuery, err = keyDB.encDB.Prepare(insertSessionStateQuery); err != nil {
		return nil, err
	}
	if keyDB.getSessionStateQuery, err = keyDB.encDB.Prepare(getSessionStateQuery); err != nil {
		return nil, err
	}
	if keyDB.updateSessionKeyQuery, err = keyDB.encDB.Prepare(updateSessionKeyQuery); err != nil {
		return nil, err
	}
	if keyDB.insertSessionKeyQuery, err = keyDB.encDB.Prepare(insertSessionKeyQuery); err != nil {
		return nil, err
	}
	if keyDB.getSessionKeyQuery, err = keyDB.encDB.Prepare(getSessionKeyQuery); err != nil {
		return nil, err
	}
	return &keyDB, nil
}

// Close the key database.
func (keyDB *KeyDB) Close() error {
	return keyDB.encDB.Close()
}

// Rekey tries to rekey the key database dbname with the newPassphrase
// (processed by a KDF with iter many iterations). The supplied oldPassphrase
// must be correct, otherwise an error is returned.
func Rekey(dbname string, oldPassphrase, newPassphrase []byte, newIter int) error {
	return encdb.Rekey(dbname, oldPassphrase, newPassphrase, newIter)
}

// Status returns the autoVacuum mode and freelistCount of keyDB.
func (keyDB *KeyDB) Status() (
	autoVacuum string,
	freelistCount int64,
	err error,
) {
	return encdb.Status(keyDB.encDB)
}

// Vacuum executes VACUUM command in keyDB. If autoVacuumMode is not nil and
// different from the current one, the auto_vacuum mode is changed before
// VACUUM is executed.
func (keyDB *KeyDB) Vacuum(autoVacuumMode string) error {
	return encdb.Vacuum(keyDB.encDB, autoVacuumMode)
}

// Incremental executes incremental_vacuum to free up to pages many pages. If
// pages is 0, all pages are freed. If the current auto_vacuum mode is not
// INCREMENTAL, an error is returned.
func (keyDB *KeyDB) Incremental(pages int64) error {
	return encdb.Incremental(keyDB.encDB, pages)
}

// AddPrivateUID adds a private uid to keyDB.
func (keyDB *KeyDB) AddPrivateUID(msg *uid.Message) error {
	_, err := keyDB.addPrivateUIDQuery.Exec(
		msg.UIDContent.IDENTITY,
		msg.UIDContent.MSGCOUNT,
		msg.JSON(),
		msg.PrivateSigKey(),
		msg.PrivateEncKey(),
		"",
	)
	if err != nil {
		return err
	}
	return nil
}

// AddPrivateUIDReply adds the msgReply to the given UID message.
func (keyDB *KeyDB) AddPrivateUIDReply(
	msg *uid.Message,
	msgReply *uid.MessageReply,
) error {
	_, err := keyDB.addPrivateUIDReplyQuery.Exec(msgReply.JSON(), msg.JSON())
	if err != nil {
		return err
	}
	return nil
}

// DelPrivateUID deletes the given UID message from keyDB.
func (keyDB *KeyDB) DelPrivateUID(msg *uid.Message) error {
	if _, err := keyDB.delPrivateUIDQuery.Exec(msg.JSON()); err != nil {
		return err
	}
	return nil
}

// GetPrivateIdentities returns all private identities from keyDB.
func (keyDB *KeyDB) GetPrivateIdentities() ([]string, error) {
	var identities []string
	rows, err := keyDB.getPrivateIdentitiesQuery.Query()
	if err != nil {
		return nil, log.Error("keydb: no private identities found")
	}
	defer rows.Close()
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return nil, log.Error(err)
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, log.Error(err)
	}
	return identities, nil
}

// GetPrivateIdentitiesForDomain returns all private identities for the given
// domain from keyDB.
func (keyDB *KeyDB) GetPrivateIdentitiesForDomain(domain string) ([]string, error) {
	var identities []string
	all, err := keyDB.GetPrivateIdentities()
	if err != nil {
		return nil, err
	}
	dmn := identity.MapDomain(domain)
	for _, id := range all {
		_, idDomain, err := identity.Split(id)
		if err != nil {
			return nil, err
		}
		if idDomain == dmn {
			identities = append(identities, id)
		}
	}
	return identities, nil
}

// GetPrivateUID gets a private uid for identity from keyDB.
//
// TODO: get all UID messages for given identity which are not expired.
func (keyDB *KeyDB) GetPrivateUID(
	identity string,
	withPrivkeys bool,
) (*uid.Message, *uid.MessageReply, error) {
	var (
		uidJSON    string
		sigPrivKey string
		encPrivKey string
		replyJSON  string
	)
	err := keyDB.getPrivateUIDQuery.QueryRow(identity).Scan(&uidJSON, &sigPrivKey, &encPrivKey, &replyJSON)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil, log.Errorf("keydb: no privkey for nym '%s' found", identity)
	case err != nil:
		return nil, nil, log.Error(err)
	default:
		msg, err := uid.NewJSON(uidJSON)
		if err != nil {
			return nil, nil, err
		}
		if err := msg.VerifySelfSig(); err != nil {
			// if this fails something is seriously wrong
			return nil, nil, log.Error(err)
		}
		if withPrivkeys {
			if err := msg.SetPrivateSigKey(sigPrivKey); err != nil {
				return nil, nil, err
			}
			if err := msg.SetPrivateEncKey(encPrivKey); err != nil {
				return nil, nil, err
			}
		}
		var msgReply *uid.MessageReply
		if replyJSON != "" {
			msgReply, err = uid.NewJSONReply(replyJSON)
			if err != nil {
				return nil, nil, err
			}
		}
		return msg, msgReply, nil
	}
}

// AddPrivateKeyInit adds a private KeyInit message and the corresponding
// server signature to keyDB.
func (keyDB *KeyDB) AddPrivateKeyInit(
	ki *uid.KeyInit,
	pubKeyHash, sigPubKey, privateKey, serverSignature string,
) error {
	_, err := keyDB.addPrivateKeyInitQuery.Exec(
		ki.SigKeyHash(),
		pubKeyHash,
		ki.JSON(),
		sigPubKey,
		privateKey,
		serverSignature,
	)
	if err != nil {
		return err
	}
	return nil
}

// GetPrivateKeyInit returns the private KeyInit for the given pubKeyHash.
func (keyDB *KeyDB) GetPrivateKeyInit(
	pubKeyHash string,
) (ki *uid.KeyInit, sigPubKey, privKey string, err error) {
	var json string
	err = keyDB.getPrivateKeyInitQuery.QueryRow(pubKeyHash).Scan(&json, &sigPubKey, &privKey)
	switch {
	case err != nil:
		return nil, "", "", log.Error(err)
	default:
		ki, err = uid.NewJSONKeyInit([]byte(json))
		if err != nil {
			return nil, "", "", err
		}
		return
	}
}

// AddPublicKeyInit adds a public KeyInit message to keyDB.
func (keyDB *KeyDB) AddPublicKeyInit(ki *uid.KeyInit) error {
	_, err := keyDB.addPublicKeyInitQuery.Exec(ki.SigKeyHash(), ki.JSON())
	if err != nil {
		return err
	}
	return nil
}

// GetPublicKeyInit gets a public key init from keydb.
// If no such KeyInit could be found, sql.ErrNoRows is returned.
func (keyDB *KeyDB) GetPublicKeyInit(sigKeyHash string) (*uid.KeyInit, error) {
	var json string
	err := keyDB.getPublicKeyInitQuery.QueryRow(sigKeyHash).Scan(&json)
	switch {
	case err != nil:
		return nil, log.Error(err)
	default:
		ki, err := uid.NewJSONKeyInit([]byte(json))
		if err != nil {
			return nil, err
		}
		return ki, nil
	}
}

// AddPublicUID adds a public UID message and it's hash chain position to
// keyDB.
func (keyDB *KeyDB) AddPublicUID(msg *uid.Message, position uint64) error {
	_, err := keyDB.addPublicUIDQuery.Exec(
		msg.UIDContent.IDENTITY,
		msg.UIDContent.MSGCOUNT,
		position,
		msg.JSON(),
	)
	if err != nil {
		return err
	}
	return nil
}

// GetPublicUID gets the public UID message from keyDB with the highest
// position smaller or equal to maxpos.
func (keyDB *KeyDB) GetPublicUID(
	identity string,
	maxpos uint64,
) (msg *uid.Message, pos uint64, found bool, err error) {
	var uidJSON string
	err = keyDB.getPublicUIDQuery.QueryRow(identity, maxpos).Scan(&uidJSON, &pos)
	switch {
	case err == sql.ErrNoRows:
		return nil, 0, false, nil
	case err != nil:
		return nil, 0, false, log.Error(err)
	default:
		msg, err = uid.NewJSON(uidJSON)
		if err != nil {
			return nil, 0, false, err
		}
		found = true
		return
	}
}

// AddHashChainEntry adds the hash chain entry at position for the given
// domain to keyDB.
func (keyDB *KeyDB) AddHashChainEntry(
	domain string,
	position uint64,
	entry string,
) error {
	dmn := identity.MapDomain(domain)
	_, err := keyDB.addHashChainEntryQuery.Exec(dmn, position, entry)
	if err != nil {
		return err
	}
	return nil
}

// GetLastHashChainPos returns the last hash chain position for the given
// domain from keydb.
// The return value found indicates if a hash chain entry for domain exists.
func (keyDB *KeyDB) GetLastHashChainPos(domain string) (
	pos uint64,
	found bool,
	err error,
) {
	dmn := identity.MapDomain(domain)
	err = keyDB.getLastHashChainPosQuery.QueryRow(dmn).Scan(&pos)
	switch {
	case err == sql.ErrNoRows:
		return 0, false, nil
	case err != nil:
		return 0, false, log.Error(err)
	default:
		return pos, true, nil
	}
}

// GetHashChainEntry returns the hash chain entry for the given domain and
// position from keydb.
func (keyDB *KeyDB) GetHashChainEntry(domain string, position uint64) (string, error) {
	var entry string
	dmn := identity.MapDomain(domain)
	err := keyDB.getHashChainEntryQuery.QueryRow(dmn, position).Scan(&entry)
	switch {
	case err != nil:
		return "", log.Error(err)
	default:
		return entry, nil
	}
}

// GetLastHashChainEntry returns the last hash chain entry for the given domain.
func (keyDB *KeyDB) GetLastHashChainEntry(domain string) (string, error) {
	dmn := identity.MapDomain(domain)
	pos, found, err := keyDB.GetLastHashChainPos(dmn)
	if err != nil {
		return "", err
	}
	if !found {
		return "", log.Errorf("keydb: no entry found for domain '%s'", dmn)
	}
	entry, err := keyDB.GetHashChainEntry(dmn, pos)
	if err != nil {
		return "", err
	}
	return entry, nil
}

// DelHashChain deletes the hash chain for the given domain.
func (keyDB *KeyDB) DelHashChain(domain string) error {
	dmn := identity.MapDomain(domain)
	if _, err := keyDB.delHashChainQuery.Exec(dmn); err != nil {
		return err
	}
	return nil
}
