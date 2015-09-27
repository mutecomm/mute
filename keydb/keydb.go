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

// TODO:
// - link Sessions to MessageKeys with foreign key?
// - how to handle old messages keys if a session is updated?

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
  ID          INTEGER PRIMARY KEY,
  IDENTITY    TEXT    NOT NULL,
  PARTNER     TEXT    NOT NULL,
  ROOTKEYHASH TEXT    NOT NULL,
  CHAINKEY    TEXT    NOT NULL
);`
	createQueryMessageKeys = `
CREATE TABLE MessageKeys (
  ID          INTEGER PRIMARY KEY,
  ROOTKEYHASH TEXT    NOT NULL,
  I           INTEGER NOT NULL,
  SEND        TEXT    NOT NULL,
  RECV        TEXT    NOT NULL
);`
	createQueryHashchains = `
CREATE TABLE Hashchains (
  ID       INTEGER PRIMARY KEY,
  DOMAIN   TEXT    NOT NULL,
  POSITION INTEGER NOT NULL,
  ENTRY    TEXT    NOT NULL
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
	getSessionQuery           = "SELECT ROOTKEYHASH FROM Sessions WHERE IDENTITY=? AND PARTNER=?;"
	insertSessionQuery        = "INSERT INTO Sessions(IDENTITY, PARTNER, ROOTKEYHASH, CHAINKEY) VALUES (?, ?, ?, ?);"
	updateSessionQuery        = "UPDATE Sessions SET ROOTKEYHASH=?, CHAINKEY=? WHERE IDENTITY=? and PARTNER=?;"
	addMessageKeyQuery        = "INSERT INTO MessageKeys(ROOTKEYHASH, I, SEND, RECV) VALUES (?, ?, ?, ?);"
	addHashChainEntryQuery    = "INSERT INTO Hashchains(DOMAIN, POSITION, ENTRY) VALUES (?, ?, ?);"
	getHashChainEntryQuery    = "SELECT ENTRY FROM Hashchains WHERE DOMAIN=? AND POSITION=?;"
	getLastHashChainPosQuery  = "SELECT POSITION FROM Hashchains WHERE DOMAIN=? ORDER BY POSITION DESC;"
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
	insertSessionQuery        *sql.Stmt
	updateSessionQuery        *sql.Stmt
	addMessageKeyQuery        *sql.Stmt
	addHashChainEntryQuery    *sql.Stmt
	getHashChainEntryQuery    *sql.Stmt
	getLastHashChainPosQuery  *sql.Stmt
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
	if keyDB.insertSessionQuery, err = keyDB.encDB.Prepare(insertSessionQuery); err != nil {
		return nil, err
	}
	if keyDB.updateSessionQuery, err = keyDB.encDB.Prepare(updateSessionQuery); err != nil {
		return nil, err
	}
	if keyDB.addMessageKeyQuery, err = keyDB.encDB.Prepare(addMessageKeyQuery); err != nil {
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

// DeletePrivateUID deletes the given UID message from keyDB.
func (keyDB *KeyDB) DeletePrivateUID(msg *uid.Message) error {
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
	for _, id := range all {
		_, idDomain, err := identity.Split(id)
		if err != nil {
			return nil, err
		}
		if idDomain == domain {
			identities = append(identities, id)
		}
	}
	return identities, nil
}

// GetPrivateUID gets a private uid for identity from keyDB.
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
		// TODO: better be safe than sorry?
		if err := msg.VerifySelfSig(); err != nil {
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
	case err == sql.ErrNoRows:
		return nil, "", "", log.Errorf("keydb: no key init for pubKeyHash '%s' found", pubKeyHash)
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
func (keyDB *KeyDB) GetPublicKeyInit(sigKeyHash string) (*uid.KeyInit, error) {
	var json string
	err := keyDB.getPublicKeyInitQuery.QueryRow(sigKeyHash).Scan(&json)
	switch {
	case err == sql.ErrNoRows:
		return nil, log.Errorf("keydb: no key init for SIGKEYHASH '%s' found", sigKeyHash)
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

// AddSession adds a session for the given identity partner pair. A session
// consists of a rootKeyHash, a chainKey and two arrays send and recv of
// sender and receiver keys. The arrays must have the same size.
func (keyDB *KeyDB) AddSession(
	identity, partner, rootKeyHash, chainKey string,
	send, recv []string,
) error {
	if len(send) != len(recv) {
		return log.Error("keydb: len(send) != len(recv)")
	}
	// store/update session
	res, err := keyDB.updateSessionQuery.Exec(rootKeyHash, chainKey, identity, partner)
	if err != nil {
		return log.Error(err)
	}
	nRows, err := res.RowsAffected()
	if err != nil {
		return log.Error(err)
	}
	if nRows == 0 {
		_, err := keyDB.insertSessionQuery.Exec(identity, partner, rootKeyHash, chainKey)
		if err != nil {
			return log.Error(err)
		}
	}
	// stores message keys
	for i := range send {
		_, err := keyDB.addMessageKeyQuery.Exec(
			rootKeyHash,
			i,
			send[i],
			recv[i],
		)
		if err != nil {
			return err
		}

	}
	return nil
}

// GetSession returns the session rootKeyHash for the given identity partner
// pair.
func (keyDB *KeyDB) GetSession(identity, partner string) (string, error) {
	var rootKeyHash string
	err := keyDB.getSessionQuery.QueryRow(identity, partner).Scan(&rootKeyHash)
	switch {
	case err == sql.ErrNoRows:
		return "", nil
	case err != nil:
		return "", log.Error(err)
	default:
		return rootKeyHash, nil
	}
}

// AddHashChainEntry adds the hash chain entry at position for the given
// domain to keyDB.
func (keyDB *KeyDB) AddHashChainEntry(
	domain string,
	position uint64,
	entry string,
) error {
	_, err := keyDB.addHashChainEntryQuery.Exec(domain, position, entry)
	if err != nil {
		return err
	}
	return nil
}

// GetLastHashChainPos returns the last hash chain position for the given
// domain from keydb.
func (keyDB *KeyDB) GetLastHashChainPos(domain string) (uint64, bool, error) {
	var pos uint64
	err := keyDB.getLastHashChainPosQuery.QueryRow(domain).Scan(&pos)
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
	err := keyDB.getHashChainEntryQuery.QueryRow(domain, position).Scan(&entry)
	switch {
	case err != nil:
		return "", log.Error(err)
	default:
		return entry, nil
	}
}

// GetLastHashChainEntry returns the last hash chain entry for the given domain.
func (keyDB *KeyDB) GetLastHashChainEntry(domain string) (string, error) {
	pos, found, err := keyDB.GetLastHashChainPos(domain)
	if err != nil {
		return "", err
	}
	if !found {
		return "", log.Errorf("keydb: no entry found for domain '%s'", domain)
	}
	entry, err := keyDB.GetHashChainEntry(domain, pos)
	if err != nil {
		return "", err
	}
	return entry, nil
}
