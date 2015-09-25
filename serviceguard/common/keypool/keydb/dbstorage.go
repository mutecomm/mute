package keydb

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"

	_ "github.com/go-sql-driver/mysql" //
)

var (
	// ErrClosed is returned if trying to work with a closed DB connection
	ErrClosed = errors.New("spendbook: DB is closed")
)

const (
	createQuery = `CREATE TABLE IF NOT EXISTS keypool (
						KeyID VARCHAR(128),
						KeyUsage VARCHAR(255),
						KeyData TEXT,
						CONSTRAINT KeyID UNIQUE (KeyID)
					);`
	selectQuery = `SELECT KeyData FROM keypool WHERE KeyID=?;`
	insertQuery = `INSERT INTO keypool (KeyID, KeyUsage, KeyData) VALUES (?, ?, ?);`
	loadQuery   = `SELECT KeyData FROM keypool;`
)

// KeyDB contains a key storage in sql database
type KeyDB struct {
	DB          *sql.DB
	selectQuery *sql.Stmt
	insertQuery *sql.Stmt
	loadQuery   *sql.Stmt
	mayClose    bool
}

// New returns a new spendbook. Takes an existing database handle or URL
func New(db interface{}) (*KeyDB, error) {
	if dbConn, ok := db.(*sql.DB); ok {
		return NewFromDB(dbConn)
	}
	return NewFromURL(db.(string))
}

// NewFromDB returns a KeyDB from an existing database handler
func NewFromDB(db *sql.DB) (*KeyDB, error) {
	if db == nil {
		return nil, ErrClosed
	}
	kd := new(KeyDB)
	kd.DB = db
	kd.mayClose = false
	err := kd.initDB()
	if err != nil {
		return nil, err
	}
	return kd, nil
}

// NewFromURL returns a KeyDB from a URL
func NewFromURL(dburl string) (*KeyDB, error) {
	db, err := sql.Open("mysql", dburl)
	if err != nil {
		return nil, err
	}
	kd := new(KeyDB)
	kd.DB = db
	kd.mayClose = true
	err = kd.initDB()
	if err != nil {
		return nil, err
	}
	return kd, nil
}

// Close the database
func (kd *KeyDB) Close() {
	if kd.mayClose {
		kd.DB.Close()
	}
	kd.DB = nil
}

func (kd *KeyDB) initDB() error {
	var err error
	kd.DB.Exec(createQuery)
	kd.insertQuery, err = kd.DB.Prepare(insertQuery)
	if err != nil {
		return err
	}
	kd.selectQuery, err = kd.DB.Prepare(selectQuery)
	if err != nil {
		return err
	}
	kd.loadQuery, err = kd.DB.Prepare(loadQuery)
	if err != nil {
		return err
	}
	return nil
}

// Add keyDB to keypool storage handlers
func Add(kp *keypool.KeyPool, db interface{}) error {
	keydb, err := New(db)
	if err != nil {
		return err
	}
	kp.RegisterStorage(keydb.fetchFunc(), keydb.writeFunc(), keydb.loadFunc())
	return nil
}

// Add keyDB to keypool storage handlers
func (kd *KeyDB) Add(kp *keypool.KeyPool) error {
	kp.RegisterStorage(kd.fetchFunc(), kd.writeFunc(), kd.loadFunc())
	return nil
}

// writeFunc returns a function ready to write keys to storage
func (kd *KeyDB) writeFunc() keypool.WriteKeyCallbackFunc {
	return func(keyid []byte, usage string, marshalledKey []byte) error {
		id := hex.EncodeToString(keyid)
		marshalled := base64.StdEncoding.EncodeToString(marshalledKey)
		_, err := kd.insertQuery.Exec(id, usage, marshalled)
		if err == nil {
			return err
		}
		return nil
	}
}

// Fetch fetches keyid from the database and returns the marshalled key
func (kd *KeyDB) Fetch(keyid []byte) (marshalledKey []byte, err error) {
	var encodedKey string
	id := hex.EncodeToString(keyid)
	err = kd.selectQuery.QueryRow(id).Scan(&encodedKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, keypool.ErrNotFound
		}
		return nil, err
	}
	marshalledKey, err = base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}
	return marshalledKey, nil
}

// fetchFunc returns a function ready to fech a key from storage
func (kd *KeyDB) fetchFunc() keypool.FetchKeyCallBackFunc {
	return kd.Fetch
}

// loadFunc returns a callback that loads keys from storage
func (kd *KeyDB) loadFunc() keypool.LoadKeysCallbackFunc {
	return func(keypool *keypool.KeyPool) error {
		rows, err := kd.loadQuery.Query()
		if err != nil {
			return err
		}
		for rows.Next() {
			var KeyData string
			err := rows.Scan(&KeyData)
			if err != nil {
				return err
			}
			marshalledKey, err := base64.StdEncoding.DecodeString(KeyData)
			if err != nil {
				return err
			}
			loadKey, err := new(signkeys.PublicKey).Unmarshal(marshalledKey)
			if err != nil {
				return err
			}
			keypool.LoadKey(loadKey) // ignore errors
		}
		return nil
	}
}
