// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mixaddr

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/curve25519"
)

// Rand is the random source for the package.
var Rand = rand.Reader

// KeySize is the size of a key.
const KeySize = 32

// KeyMap maps a public key to a private key.
type KeyMap map[[KeySize]byte]KeyEntry

// KeyEntry contains a mix address, public and private keys.
type KeyEntry struct {
	Pubkey, Privkey []byte // The mix public and private keys
	Expire          int64  // Time the key expires
	Address         string // The address where the mix listens
	TokenKey        []byte // The token key of that mix
}

// KeyList is a mix-side implementation of public and private key management.
type KeyList struct {
	Keys            KeyMap
	PrivateKey      *[ed25519.PrivateKeySize]byte
	PublicKey       *[ed25519.PublicKeySize]byte
	Address         string
	Duration        int64
	NewKeyFrequency int64
	Safedir         string
	statement       *AddressStatement
	stopchan        chan bool
	mutex           *sync.Mutex
}

// New returns a new KeyList.
func New(PrivateKey *[ed25519.PrivateKeySize]byte, address string, duration, newKeyFrequency int64, safedir string) *KeyList {
	kl := new(KeyList)
	kl.PrivateKey = PrivateKey
	pubkey := getPubKey(PrivateKey)
	kl.PublicKey = pubkey
	kl.Keys = make(KeyMap)
	kl.Address = address
	kl.NewKeyFrequency = newKeyFrequency
	kl.Duration = duration
	kl.Safedir = safedir
	os.MkdirAll(safedir, 0700)
	kl.mutex = new(sync.Mutex)
	kl.stopchan = make(chan bool)
	return kl
}

// GetPrivateKey returns the private key for a public key, if known.
func (kl *KeyList) GetPrivateKey(pubkey *[KeySize]byte) *[KeySize]byte {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	if keyEntry, ok := kl.Keys[*pubkey]; ok {
		if keyEntry.Expire < timeNow() {
			return nil
		}
		privkey := new([KeySize]byte)
		copy(privkey[:], keyEntry.Privkey)
		return privkey
	}
	return nil
}

// GetKeyEntry returns the key entry or nil.
func (kl *KeyList) GetKeyEntry(pubkey *[KeySize]byte) *KeyEntry {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	if keyEntry, ok := kl.Keys[*pubkey]; ok {
		if keyEntry.Expire < timeNow() {
			return nil
		}
		return &keyEntry
	}
	return nil
}

// Maintain starts two routines that maintain the key list in memory.
func (kl *KeyList) Maintain() {
	kl.stopchan = make(chan bool)
	go func() {
		var lastAdd int64
		addTicker := time.NewTicker(time.Second * 10)
		for {
			select {
			case <-kl.stopchan:
				// Stop maintainer
				return
			case <-addTicker.C:
				if lastAdd < timeNow()-kl.NewKeyFrequency {
					lastAdd = timeNow()
					kl.AddKey()
				} else {
					kl.Expire()
				}
			}
		}
	}()
}

// Marshal the keylist.
func (kl KeyList) Marshal() []byte {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	return kl.marshal()
}

func (kl KeyList) marshal() []byte {
	klist := make([]KeyEntry, 0, len(kl.Keys))
	for _, e := range kl.Keys {
		klist = append(klist, e)
	}
	d, err := json.MarshalIndent(klist, "", "    ")
	if err != nil {
		panic(err) // Should never happen
	}
	return d
}

// Unmarshal a keylist.
func (kl *KeyList) Unmarshal(d []byte) error {
	var klist []KeyEntry
	err := json.Unmarshal(d, &klist)
	if err != nil {
		return err
	}
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	kl.Keys = make(KeyMap)
	for _, e := range klist {
		var Pubkey [KeySize]byte
		copy(Pubkey[:], e.Pubkey)
		kl.Keys[Pubkey] = e
	}
	kl.expire()
	kl.updateStatement()
	return nil
}

// GetBoundaryTime gets the first and last expire from the list.
func (kl *KeyList) GetBoundaryTime() (first, last int64) {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	for _, e := range kl.Keys {
		if e.Expire <= first || first == 0 {
			first = e.Expire
		}
		if e.Expire >= last || last == 0 {
			last = e.Expire
		}
	}
	return
}

// Expire does an expire run on the keylist.
func (kl *KeyList) Expire() {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	kl.expire()
}

// Expire does an expire run on the keylist.
func (kl *KeyList) expire() {
	var expired [][KeySize]byte
	now := timeNow()
	for k, e := range kl.Keys {
		if e.Expire < now {
			expired = append(expired, k)
		}
	}
	for _, k := range expired {
		delete(kl.Keys, k)
	}
}

// AddKey adds a key to the list.
func (kl *KeyList) AddKey() {
	pubkey, privkey, err := genKey()
	if err != nil {
		panic(err) // Should never happen
	}
	ke := KeyEntry{
		Pubkey:   pubkey[:],
		Privkey:  privkey[:],
		Expire:   timeNow() + kl.Duration,
		Address:  kl.Address,
		TokenKey: kl.PublicKey[:],
	}
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	kl.Keys[*pubkey] = ke
	kl.saveKeys()
	kl.updateStatement()
}

func (kl *KeyList) saveKeys() {
	file := filepath.Join(kl.Safedir, "keys."+strconv.FormatInt(timeNow(), 10))
	ioutil.WriteFile(file, kl.marshal(), 0600)
}

// UpdateStatement sets the statement of the list.
func (kl *KeyList) updateStatement() {
	al := make(AddressList, 0, len(kl.Keys))
	for _, key := range kl.Keys {
		al = append(al, Address{
			Pubkey:   key.Pubkey,
			Expire:   key.Expire,
			Address:  key.Address,
			TokenKey: key.TokenKey,
		})
	}
	tst := al.Statement(kl.PrivateKey)
	kl.statement = &tst
}

// GetStatement returns the current key statement.
func (kl *KeyList) GetStatement() *AddressStatement {
	kl.mutex.Lock()
	defer kl.mutex.Unlock()
	return kl.statement
}

// genKey returns a keypair
func genKey() (pub, priv *[KeySize]byte, err error) {
	publicKey := new([KeySize]byte)
	privateKey := new([KeySize]byte)
	if _, err := io.ReadFull(Rand, privateKey[:]); err != nil {
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return publicKey, privateKey, nil
}
