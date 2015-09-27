// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package walletstore implements a wallet storage
package walletstore

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	mathrand "math/rand"
	"sync"

	"github.com/agl/ed25519"
	_ "github.com/go-sql-driver/mysql" // remove after tests
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/serviceguard/common/constants"
	"github.com/mutecomm/mute/util/times"
)

const (
	createQueryTokens = `CREATE TABLE IF NOT EXISTS walletTokens (
							LockTime INT NOT NULL,
							LockID INT NOT NULL,
							Hash CHAR(64) NOT NULL,
							Token TEXT NOT NULL,
							OwnerPubKey VARCHAR(255) NOT NULL,
							OwnerPrivKey VARCHAR(255) NOT NULL,
							Renewable bool NOT NULL,
							CanReissue bool NOT NULL,
							UsageStr VARCHAR(255) NOT NULL,
							Expire INT UNSIGNED NOT NULL,
							OwnedSelf bool NOT NULL,
							HasParams bool NOT NULL,
							HasState bool NOT NULL,
							CONSTRAINT Hash UNIQUE (Hash)
						);`
	createQueryState = `CREATE TABLE IF NOT EXISTS walletState (
							Hash CHAR(64),
							State TEXT,
							CONSTRAINT Hash UNIQUE (Hash)
						);`
	setTokenQuery = `INSERT INTO walletTokens (LockTime, LockID, Hash, Token, OwnerPubKey, OwnerPrivKey, Renewable, CanReissue,
						 UsageStr, Expire, OwnedSelf, HasParams, HasState) VALUES (0,0,?,?,?,?,?,?,?,?,?,?,?);`
	setTokenUpdateQuery = `UPDATE walletTokens SET Hash=?, Token=?, OwnerPubKey=?, OwnerPrivKey=?, 
						Renewable=?, CanReissue=?, UsageStr=?, Expire=?, OwnedSelf=?, 
						HasParams=?, HasState=? WHERE Hash=?;`
	getTokenQuery = `SELECT LockID, Hash, Token, OwnerPubKey, OwnerPrivKey, Renewable, 
						CanReissue, UsageStr, Expire, OwnedSelf, HasParams, HasState
						FROM walletTokens WHERE Hash=?;`
	setStateQuery       = `INSERT INTO walletState (Hash, State) VALUES (?,?);`
	setStateUpdateQuery = `UPDATE walletState SET State=? WHERE Hash=?;`
	cleanLocksQuery     = "UPDATE walletTokens SET LockTime=0, LockID=0 WHERE LockTime!=0 AND LockTime<?;"
	lockQuery           = "UPDATE walletTokens SET LockID=?, LockTime=? WHERE Hash=? AND LockID=0 OR LockID=?;"
	unlockQuery         = "UPDATE walletTokens SET LockID=0,LockTime=0 WHERE Hash=?;"
	deleteTokenQuery    = "DELETE FROM walletTokens WHERE Hash=?;"
	deleteStateQuery    = "DELETE FROM walletState WHERE Hash=?;"
	getStateQuery       = `SELECT Hash, State FROM walletState WHERE Hash=?;`
	findTokenSelfQuery  = `SELECT Hash FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=1 AND UsageStr=? ORDER BY Expire ASC LIMIT 1;`
	findTokenOwnerQuery = `SELECT Hash FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=0 AND OwnerPubKey=? AND UsageStr=? ORDER BY Expire ASC LIMIT 1;`
	findTokenAnyQuery   = `SELECT Hash FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=0 AND UsageStr=? ORDER BY Expire ASC LIMIT 1;`
	getExpireQuery      = `SELECT Hash FROM walletTokens WHERE LockID=0 AND Renewable=1 AND HasState=0 AND HasParams=0 AND OwnedSelf=1 AND Expire<? ORDER BY Expire ASC LIMIT 1;`
	getReissueQuery     = `SELECT Hash FROM walletTokens WHERE LockID=0 AND HasState=1 ORDER BY Expire ASC LIMIT 1;`
	countOwnQuery       = `SELECT COUNT(*) FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=1 AND UsageStr=?;`
	countOwnerQuery     = `SELECT COUNT(*) FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=0 AND UsageStr=? AND OwnerPubKey=?;`
	countAnyQuery       = `SELECT COUNT(*) FROM walletTokens WHERE LockID=0 AND HasState=0 AND OwnedSelf=0 AND UsageStr=?;`
	finalExpireQuery    = `SELECT Hash FROM walletTokens WHERE Expire<? LIMIT 10;`
)

// MaxLockAge is the maximum time a lock may persist
var MaxLockAge = constants.ClientMaxLockAge

// ExpireEdge is the time in which to renew an expiring token
var ExpireEdge = constants.ClientExpireEdge

// Storage implements an SQL-backed WalletStore interface
type Storage struct {
	DB                  *sql.DB
	setTokenQuery       *sql.Stmt
	setTokenUpdateQuery *sql.Stmt
	setStateQuery       *sql.Stmt
	setStateUpdateQuery *sql.Stmt
	lockQuery           *sql.Stmt
	cleanLocksQuery     *sql.Stmt
	unlockQuery         *sql.Stmt
	deleteTokenQuery    *sql.Stmt
	deleteStateQuery    *sql.Stmt
	getTokenQuery       *sql.Stmt
	getStateQuery       *sql.Stmt
	findTokenSelfQuery  *sql.Stmt
	findTokenOwnerQuery *sql.Stmt
	findTokenAnyQuery   *sql.Stmt
	getExpireQuery      *sql.Stmt
	getReissueQuery     *sql.Stmt
	countOwnQuery       *sql.Stmt
	countOwnerQuery     *sql.Stmt
	countAnyQuery       *sql.Stmt
	finalExpireQuery    *sql.Stmt
	cacheMutex          *sync.RWMutex
	cache               *CacheData
}

// New returns a new Storage, takes existing DB connection or URL as parameter
func New(db interface{}) (*Storage, error) {
	if dbConn, ok := db.(*sql.DB); ok {
		return NewFromDB(dbConn)
	}
	return NewFromURL(db.(string))
}

// NewFromDB returns a storage for an existing database connection
func NewFromDB(db *sql.DB) (*Storage, error) {
	ws := new(Storage)
	ws.DB = db
	err := ws.initDB()
	if err != nil {
		return nil, err
	}
	return ws, nil
}

// NewFromURL returns a Storage from a URL
func NewFromURL(dburl string) (*Storage, error) {
	db, err := sql.Open("mysql", dburl)
	if err != nil {
		return nil, err
	}
	ws := new(Storage)
	ws.DB = db
	err = ws.initDB()
	if err != nil {
		return nil, err
	}
	return ws, nil
}

func (ws *Storage) initDB() (err error) {
	ws.cacheMutex = new(sync.RWMutex)
	ws.DB.Exec(createQueryTokens)
	ws.DB.Exec(createQueryState)
	if ws.setTokenQuery, err = ws.DB.Prepare(setTokenQuery); err != nil {
		return err
	}
	if ws.setTokenUpdateQuery, err = ws.DB.Prepare(setTokenUpdateQuery); err != nil {
		return err
	}
	if ws.setStateQuery, err = ws.DB.Prepare(setStateQuery); err != nil {
		return err
	}
	if ws.setStateUpdateQuery, err = ws.DB.Prepare(setStateUpdateQuery); err != nil {
		return err
	}
	if ws.lockQuery, err = ws.DB.Prepare(lockQuery); err != nil {
		return err
	}
	if ws.cleanLocksQuery, err = ws.DB.Prepare(cleanLocksQuery); err != nil {
		return err
	}
	if ws.unlockQuery, err = ws.DB.Prepare(unlockQuery); err != nil {
		return err
	}
	if ws.deleteTokenQuery, err = ws.DB.Prepare(deleteTokenQuery); err != nil {
		return err
	}
	if ws.deleteStateQuery, err = ws.DB.Prepare(deleteStateQuery); err != nil {
		return err
	}
	if ws.getTokenQuery, err = ws.DB.Prepare(getTokenQuery); err != nil {
		return err
	}
	if ws.getStateQuery, err = ws.DB.Prepare(getStateQuery); err != nil {
		return err
	}
	if ws.findTokenSelfQuery, err = ws.DB.Prepare(findTokenSelfQuery); err != nil {
		return err
	}
	if ws.findTokenOwnerQuery, err = ws.DB.Prepare(findTokenOwnerQuery); err != nil {
		return err
	}
	if ws.findTokenAnyQuery, err = ws.DB.Prepare(findTokenAnyQuery); err != nil {
		return err
	}
	if ws.getExpireQuery, err = ws.DB.Prepare(getExpireQuery); err != nil {
		return err
	}
	if ws.getReissueQuery, err = ws.DB.Prepare(getReissueQuery); err != nil {
		return err
	}
	if ws.countOwnQuery, err = ws.DB.Prepare(countOwnQuery); err != nil {
		return err
	}
	if ws.countOwnerQuery, err = ws.DB.Prepare(countOwnerQuery); err != nil {
		return err
	}
	if ws.countAnyQuery, err = ws.DB.Prepare(countAnyQuery); err != nil {
		return err
	}
	if ws.finalExpireQuery, err = ws.DB.Prepare(finalExpireQuery); err != nil {
		return err
	}
	ws.CleanLocks(false)
	return nil
}

// CleanLocks cleans all locks. If force is true all locks are removed, not only expired locks
func (ws *Storage) CleanLocks(force bool) {
	locktime := times.Now() + MaxLockAge
	if force {
		locktime = int64(^uint32(0)) // MaxUInt32
	}
	ws.cleanLocksQuery.Exec(locktime)
}

// SetToken writes a token to the walletstore. repeated calls update the entry of tokenEntry.Hash is the same
func (ws *Storage) SetToken(tokenEntry client.TokenEntry) error {
	global, state := encodeToken(&tokenEntry)
	_, err := ws.setTokenQuery.Exec(global.Hash, global.Token, global.OwnerPubKey,
		global.OwnerPrivKey, global.Renewable, global.CanReissue,
		global.Usage, global.Expire, global.OwnedSelf,
		global.HasParams, global.HasState)
	if err != nil {
		_, err := ws.setTokenUpdateQuery.Exec(global.Hash, global.Token, global.OwnerPubKey,
			global.OwnerPrivKey, global.Renewable, global.CanReissue,
			global.Usage, global.Expire, global.OwnedSelf,
			global.HasParams, global.HasState, global.Hash)
		if err != nil {
			return err
		}
	}
	if len(state) > 0 {
		_, err = ws.setStateQuery.Exec(global.Hash, state)
		if err != nil {
			_, err = ws.setStateUpdateQuery.Exec(state, global.Hash)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// GetToken returns the token identified by tokenHash. If lockID>=0, enforce lock (return ErrLocked)
func (ws *Storage) GetToken(tokenHash []byte, lockID int64) (tokenEntry *client.TokenEntry, err error) {
	var state, tmp string
	var lockIDDB int64
	tokenHashS := hex.EncodeToString(tokenHash)
	tokenDB := TokenEntryDBGlobal{}
	err = ws.getTokenQuery.QueryRow(tokenHashS).Scan(
		&lockIDDB, &tokenDB.Hash, &tokenDB.Token,
		&tokenDB.OwnerPubKey, &tokenDB.OwnerPrivKey, &tokenDB.Renewable,
		&tokenDB.CanReissue, &tokenDB.Usage, &tokenDB.Expire,
		&tokenDB.OwnedSelf, &tokenDB.HasParams, &tokenDB.HasState,
	)
	if err != nil {
		return nil, err
	}
	if lockID >= 0 && lockIDDB != 0 && lockIDDB != lockID {
		return nil, client.ErrLocked
	}
	if tokenDB.HasParams || tokenDB.HasState {
		err = ws.getStateQuery.QueryRow(tokenHashS).Scan(&tmp, &state)
		if err != nil {
			return nil, err
		}
	}
	return decodeToken(&tokenDB, state)
}

// DelToken deletes the token identified by tokenHash
func (ws *Storage) DelToken(tokenHash []byte) {
	tokenHashS := hex.EncodeToString(tokenHash)
	ws.deleteTokenQuery.Exec(tokenHashS)
	ws.deleteStateQuery.Exec(tokenHashS)
}

func getLockID() int64 {
	mathrand.Seed(times.NowNano())
	lockID := mathrand.Int31()
	return int64(lockID)
}

// LockToken locks token against other use. Return lockID > 0 on success, <0 on failure
func (ws *Storage) LockToken(tokenHash []byte) int64 {
	lockID := getLockID()
	tokenHashS := hex.EncodeToString(tokenHash)
	lockTime := times.Now()

	res, err := ws.lockQuery.Exec(lockID, lockTime, tokenHashS, lockID)
	if err != nil || res == nil {
		return -1
	}
	if num, _ := res.RowsAffected(); num == 0 {
		return -1
	}
	return lockID
}

// UnlockToken unlocks a locked token
func (ws *Storage) UnlockToken(tokenHash []byte) {
	tokenHashS := hex.EncodeToString(tokenHash)
	ws.unlockQuery.Exec(tokenHashS)
}

// writeCache writes the cache to database
func (ws *Storage) writeCache() error {
	ws.cacheMutex.Lock()
	defer ws.cacheMutex.Unlock()
	data := ws.cache.Marshal()
	_, err := ws.setStateQuery.Exec("CONFIGCACHE", data)
	if err != nil {
		_, err = ws.setStateUpdateQuery.Exec(data, "CONFIGCACHE")
		if err != nil {
			return err
		}
	}
	return nil
}

// readCache reads the cache from the database
func (ws *Storage) readCache() {
	var data string
	ws.cacheMutex.Lock()
	defer ws.cacheMutex.Unlock()
	err := ws.getStateQuery.QueryRow("CONFIGCACHE").Scan(&data)
	if err != nil {
		return
	}
	dataU, err := new(CacheData).Unmarshal(data)
	if err != nil {
		return
	}
	ws.cache = dataU
}

// SetVerifyKeys saves verification keys
func (ws *Storage) SetVerifyKeys(verifyKeys [][ed25519.PublicKeySize]byte) {
	ws.cacheMutex.Lock()
	if ws.cache == nil {
		ws.cache = new(CacheData)
	}
	ws.cache.VerifyKeys = verifyKeys
	ws.cacheMutex.Unlock()
	ws.writeCache()
}

// GetVerifyKeys loads verification keys
func (ws *Storage) GetVerifyKeys() [][ed25519.PublicKeySize]byte {
	ws.cacheMutex.RLock()
	if ws.cache == nil {
		ws.cacheMutex.RUnlock()
		ws.readCache()
		ws.cacheMutex.RLock()
	}
	if ws.cache == nil {
		ws.cache = new(CacheData)
	}
	if ws.cache.VerifyKeys == nil {
		ws.cache.VerifyKeys = make([][ed25519.PublicKeySize]byte, 0)
	}
	defer ws.cacheMutex.RUnlock()
	return ws.cache.VerifyKeys
}

// SetAuthToken stores an authtoken and tries
func (ws *Storage) SetAuthToken(authToken []byte, tries int) error {
	ws.cacheMutex.Lock()
	if ws.cache == nil {
		ws.cache = new(CacheData)
	}
	ws.cache.AuthToken = authToken
	ws.cache.AuthTries = tries
	ws.cacheMutex.Unlock()
	return ws.writeCache()
}

// GetAuthToken gets authtoken from store
func (ws *Storage) GetAuthToken() (authToken []byte, tries int) {
	ws.cacheMutex.RLock()
	if ws.cache == nil {
		ws.cacheMutex.RUnlock()
		ws.readCache()
		ws.cacheMutex.RLock()
	}
	defer ws.cacheMutex.RUnlock()
	if ws.cache == nil {
		return nil, 0
	}
	return ws.cache.AuthToken, ws.cache.AuthTries
}

// GetAndLockToken returns a token matching usage and optional owner. Must return ErrNoToken if no token is in store
func (ws *Storage) GetAndLockToken(usage string, owner *[ed25519.PublicKeySize]byte) (*client.TokenEntry, error) {
LookupLoop:
	for i := 0; i < 5; i++ {
		token, err := ws.getAndLockToken(usage, owner)
		if err == client.ErrLocked {
			continue LookupLoop
		}
		return token, err
	}
	return nil, client.ErrNoToken
}

func (ws *Storage) getAndLockToken(usage string, owner *[ed25519.PublicKeySize]byte) (*client.TokenEntry, error) {
	var hashS string
	var err error
	// Find only those that are not owned by self
	if owner != nil {
		ownerS := base64.StdEncoding.EncodeToString(owner[:])
		err = ws.findTokenOwnerQuery.QueryRow(ownerS, usage).Scan(&hashS)
	} else {
		err = ws.findTokenAnyQuery.QueryRow(usage).Scan(&hashS)
	}
	if err != nil {
		return nil, client.ErrNoToken
	}
	tokenHash, err := hex.DecodeString(hashS)
	if err != nil {
		return nil, client.ErrNoToken
	}
	lockID := ws.LockToken(tokenHash)
	if lockID <= 0 {
		return nil, client.ErrLocked
	}
	return ws.GetToken(tokenHash, lockID)
}

// FindToken finds a token owned by self that has usage set
func (ws *Storage) FindToken(usage string) (*client.TokenEntry, error) {
	// Find only those that ARE owned by self
	var Hash string
	err := ws.findTokenSelfQuery.QueryRow(usage).Scan(&Hash)
	if err != nil {
		return nil, client.ErrNoToken
	}
	tokenHash, err := hex.DecodeString(Hash)
	if err != nil {
		return nil, client.ErrNoToken
	}
	return ws.GetToken(tokenHash, -1)
}

// GetExpire returns the first expiring tokenHash or nil
func (ws *Storage) GetExpire() []byte {
	var hashS string
	expireLimit := times.Now() + ExpireEdge
	err := ws.getExpireQuery.QueryRow(expireLimit).Scan(&hashS)
	if err != nil {
		return nil
	}
	tokenHash, err := hex.DecodeString(hashS)
	if err != nil {
		return nil
	}
	return tokenHash
}

// GetInReissue returns the first token that has an active reissue that is not finished
func (ws *Storage) GetInReissue() []byte {
	var hashS string
	err := ws.getReissueQuery.QueryRow().Scan(&hashS)
	if err != nil {
		return nil
	}
	tokenHash, err := hex.DecodeString(hashS)
	if err != nil {
		return nil
	}
	return tokenHash
}

// GetBalanceOwn returns the number of usable tokens available for usage that are owned by self
func (ws *Storage) GetBalanceOwn(usage string) int64 {
	var count int64
	err := ws.countOwnQuery.QueryRow(usage).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// GetBalance returns the number of usable tokens available for usage owned by owner or not self (if owner==nil)
func (ws *Storage) GetBalance(usage string, owner *[ed25519.PublicKeySize]byte) int64 {
	var count int64
	var err error
	if owner != nil {
		ownerS := base64.StdEncoding.EncodeToString(owner[:])
		err = ws.countOwnerQuery.QueryRow(usage, ownerS).Scan(&count)
	} else {
		err = ws.countAnyQuery.QueryRow(usage).Scan(&count)
	}
	if err != nil {
		return 0
	}
	return count
}

// ExpireUnusable expires all tokens that cannot be used anymore (expired). Returns bool if it should be called
// again since it only expires 10 tokens at a time
func (ws *Storage) ExpireUnusable() bool {
	var hashS string
	var counted int
	var tokens [][]byte
	expireTime := times.Now() - ExpireEdge
	rows, err := ws.finalExpireQuery.Query(expireTime)
	if err != nil {
		return false
	}

	for rows.Next() {
		if err := rows.Scan(&hashS); err == nil {
			tokenHash, err := hex.DecodeString(hashS)
			if err == nil {
				counted++
				tokens = append(tokens, tokenHash)
			}
		}
	}
	rows.Close()
	for _, token := range tokens {
		ws.DelToken(token)
	}
	if counted >= 10 {
		return true
	}
	return false
}
