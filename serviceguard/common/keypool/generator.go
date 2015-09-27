// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keypool implements a key generation and lookup service for blind signature keys
package keypool

import (
	"errors"
	"sync"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/util/times"
)

var (
	// ErrNotFound is returned if the keyid could not be found in the keypool
	ErrNotFound = errors.New("keypool: Not found")
	// ErrNoGenerator is returned if Current() is called on a keypool that has no private signature key
	ErrNoGenerator = errors.New("keypool: Not a generator")
	// ErrBadUsage is returned if a key to load does not match the usage configuration
	ErrBadUsage = errors.New("keypool: Bad usage setting of key")
	// ErrExpired is returned if a key has already expired
	ErrExpired = errors.New("keypool: Expired key")
	// ErrBadSigner is returned if a key signature cannot be verified
	ErrBadSigner = errors.New("keypool: Bad signature")
	// ErrExists is returned if a key to load is already loaded
	ErrExists = errors.New("keypool: Key exists")
)

type (
	// FetchKeyCallBackFunc callback function to read keys from storage.
	// Argument is the keyid, return is the marshalled key or error
	FetchKeyCallBackFunc func(keyid []byte) (marshalledKey []byte, err error)
	// WriteKeyCallbackFunc callback function to write keys to storage.
	// Arguments are the keyid and the marshalled key
	WriteKeyCallbackFunc func(keyid []byte, usage string, marshalledKey []byte) error
	// LoadKeysCallbackFunc callback function to load many keys from storage
	// Argument is the keypool to add the keys to
	LoadKeysCallbackFunc func(keypool *KeyPool) error
)

// KeyPool implements a key pool configuration.
type KeyPool struct {
	Generator     *signkeys.KeyGenerator
	KeyDir        string                                           // Where to save keys
	keys          map[[signkeys.KeyIDSize]byte]*signkeys.PublicKey // contains past private keys
	VerifyPubKeys map[[ed25519.PublicKeySize]byte]bool             // keys to verify against
	currentKey    *signkeys.KeyPair                                // contains our current key
	previousKey   *signkeys.KeyPair                                // the previous currentKey, for param rollover
	mapMutex      *sync.RWMutex                                    // Mutex for key generation. Only one key is generated at a time

	// FetchKeyCallBack callback function to read keys from storage.
	// Argument is the keyid, return is the marshalled key or error
	FetchKeyCallBack FetchKeyCallBackFunc
	// WriteKeyCallback callback function to write keys to storage.
	// Arguments are the keyid and the marshalled key
	WriteKeyCallback WriteKeyCallbackFunc
	// LoadKeysCallback callback function to load many keys from storage
	// Argument is the keypool to add the keys to
	LoadKeysCallback LoadKeysCallbackFunc
}

// New returns a new KeyPool. The generator may require additional settings (Usage, Expire). Those should be set before calling New.
func New(generator *signkeys.KeyGenerator) *KeyPool {
	kp := new(KeyPool)
	kp.Generator = generator
	kp.keys = make(map[[signkeys.KeyIDSize]byte]*signkeys.PublicKey)
	kp.VerifyPubKeys = make(map[[ed25519.PublicKeySize]byte]bool)
	kp.mapMutex = new(sync.RWMutex)
	return kp
}

// AddVerifyKey adds key to the list of verification keys.
func (kp *KeyPool) AddVerifyKey(key *[ed25519.PublicKeySize]byte) {
	kp.mapMutex.Lock()
	defer kp.mapMutex.Unlock()
	kp.VerifyPubKeys[*key] = true
}

// ListVerifyKeys lists all known verification keys.
func (kp KeyPool) ListVerifyKeys() [][ed25519.PublicKeySize]byte {
	kp.mapMutex.Lock()
	defer kp.mapMutex.Unlock()
	ret := make([][ed25519.PublicKeySize]byte, 0, len(kp.VerifyPubKeys))
	for key := range kp.VerifyPubKeys {
		ret = append(ret, key)
	}
	return ret
}

// HasVerifyKey verifies that a verification key exists.
func (kp *KeyPool) HasVerifyKey(key *[ed25519.PublicKeySize]byte, nolock bool) bool {
	if !nolock {
		kp.mapMutex.RLock()
		defer kp.mapMutex.RUnlock()
	}
	_, ok := kp.VerifyPubKeys[*key]
	return ok
}

// Lookup a public key from keypool.
func (kp *KeyPool) Lookup(keyid [signkeys.KeyIDSize]byte) (*signkeys.PublicKey, error) {
	kp.mapMutex.RLock()
	defer kp.mapMutex.RUnlock()
	key, err := kp.lookup(keyid)
	if err == ErrNotFound && kp.FetchKeyCallBack != nil {
		// Use fetchkey callback
		fetchedKeyMarshalled, err := kp.FetchKeyCallBack(keyid[:])
		if err != nil {
			return nil, err
		}
		fetchedKey, err := new(signkeys.PublicKey).Unmarshal(fetchedKeyMarshalled)
		if err != nil {
			return nil, err
		}
		keyidFetch, err := kp.loadKey(fetchedKey)
		if err != nil && err != ErrExists {
			return nil, ErrNotFound
		}
		if *keyidFetch == keyid {
			return fetchedKey, nil
		}
	}
	return key, err
}

// lookup a public key from keypool without lock
func (kp *KeyPool) lookup(keyid [signkeys.KeyIDSize]byte) (*signkeys.PublicKey, error) {
	if d, ok := kp.keys[keyid]; ok {
		if d.Expire > times.Now() {
			return d, nil
		}
		return nil, ErrExpired
	}
	return nil, ErrNotFound
}

// SaveKey writes keyid to the keydir
func (kp KeyPool) SaveKey(keyid [signkeys.KeyIDSize]byte) error {
	kp.mapMutex.RLock()
	defer kp.mapMutex.RUnlock()
	return kp.SaveKeyUnsafe(keyid)
}

// SaveKeyUnsafe writes keyid to the keydir. Unsafe. No mutex. Only within callbacks.
func (kp KeyPool) SaveKeyUnsafe(keyid [signkeys.KeyIDSize]byte) error {
	key, err := kp.lookup(keyid)
	if err != nil {
		return err
	}
	return kp.WriteKey(key)
}

// Current returns the current key and the previous key.
func (kp *KeyPool) Current() (*signkeys.KeyPair, *signkeys.KeyPair, error) {
	if kp.Generator.PrivateKey == nil {
		return nil, nil, ErrNoGenerator
	}
	generate := false
	kp.mapMutex.Lock()
	defer kp.mapMutex.Unlock()
	if kp.currentKey == nil {
		// Always generate if we dont have one yet
		generate = true
	} else if kp.currentKey.PublicKey.Expire < times.Now()-kp.Generator.ExpireTime/2 {
		// Key has half expired, generate new one
		generate = true
	}
	if generate {
		newKey, err := kp.Generator.GenKey()
		if err != nil {
			return nil, nil, err
		}
		// Write currentKey to file
		err = kp.WriteKey(&newKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		if kp.currentKey != nil {
			kp.previousKey = kp.currentKey
		}
		kp.currentKey = newKey
		kp.keys[kp.currentKey.PublicKey.KeyID] = &newKey.PublicKey
	}
	return kp.currentKey, kp.previousKey, nil
}

// LoadKey adds a single key to the keypool.
func (kp *KeyPool) LoadKey(loadKey *signkeys.PublicKey) (*[signkeys.KeyIDSize]byte, error) {
	kp.mapMutex.Lock()
	defer kp.mapMutex.Unlock()
	return kp.loadKey(loadKey)
}

// LoadKeyUnsafe adds a single key to the keypool. Without Mutex. be careful. only for use in callback.
func (kp *KeyPool) LoadKeyUnsafe(loadKey *signkeys.PublicKey) (*[signkeys.KeyIDSize]byte, error) {
	return kp.loadKey(loadKey)
}

// loadKey adds a single key to the keypool. Without lock.
func (kp *KeyPool) loadKey(loadKey *signkeys.PublicKey) (*[signkeys.KeyIDSize]byte, error) {
	if kp.Generator.Usage != "" && loadKey.Usage != kp.Generator.Usage {
		// Don't load if usage is a mismatch
		return nil, ErrBadUsage
	}
	if loadKey.Expire < times.Now() {
		// Don't load expired keys
		return nil, ErrExpired
	}
	if !kp.HasVerifyKey(&loadKey.Signer, true) {
		// Don't load keys without matching signature
		return nil, ErrBadSigner
	}
	if !loadKey.Verify(&loadKey.Signer) {
		// Don't load keys without matching signature
		return nil, ErrBadSigner
	}
	if _, exists := kp.keys[loadKey.KeyID]; exists {
		return &loadKey.KeyID, ErrExists
	}
	kp.keys[loadKey.KeyID] = loadKey
	return &loadKey.KeyID, nil
}

// Load calls the load callback chain to load keys from storage
func (kp *KeyPool) Load() error {
	if kp.LoadKeysCallback != nil {
		return kp.LoadKeysCallback(kp)
	}
	return nil
}

// WriteKey calls the write callback chain to write keys to storage
func (kp KeyPool) WriteKey(key *signkeys.PublicKey) error {
	// Write currentKey to file
	data, err := key.Marshal()
	if err != nil {
		return err
	}
	if kp.WriteKeyCallback != nil {
		err := kp.WriteKeyCallback(key.KeyID[:], key.Usage, data)
		if err != nil {
			return err
		}
	}
	return nil
}

// RegisterStorage registers a storage backend.
func (kp *KeyPool) RegisterStorage(fetchFunc FetchKeyCallBackFunc, writeFunc WriteKeyCallbackFunc, loadFunc LoadKeysCallbackFunc) {
	if fetchFunc != nil {
		oldFetch := kp.FetchKeyCallBack
		kp.FetchKeyCallBack = func(keyid []byte) (marshalledKey []byte, err error) {
			if oldFetch != nil {
				marshalledKey, err = oldFetch(keyid)
				if err == nil {
					return marshalledKey, err
				}
			}
			return fetchFunc(keyid)
		}
	}
	if writeFunc != nil {
		oldWrite := kp.WriteKeyCallback
		kp.WriteKeyCallback = func(keyid []byte, usage string, marshalledKey []byte) error {
			if oldWrite != nil {
				err := oldWrite(keyid, usage, marshalledKey)
				if err != nil {
					return err
				}
			}
			return writeFunc(keyid, usage, marshalledKey)
		}
	}
	if loadFunc != nil {
		oldLoad := kp.LoadKeysCallback
		kp.LoadKeysCallback = func(keypool *KeyPool) error {
			if oldLoad != nil {
				err := oldLoad(keypool)
				if err != nil {
					return err
				}
			}
			return loadFunc(keypool)
		}
	}
}
