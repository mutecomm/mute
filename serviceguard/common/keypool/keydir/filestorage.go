// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keydir

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
)

// Add adds keydir storage to a keypool
func Add(kp *keypool.KeyPool, keyDir string) error {
	err := os.MkdirAll(keyDir, 0700)
	if err != nil {
		return err
	}
	kp.RegisterStorage(nil, writeKeyToDir(keyDir), loadKeysFromDir(keyDir))
	return nil
}

// writeKeyToDir returns a callback that writes key to the keydir
func writeKeyToDir(keyDir string) keypool.WriteKeyCallbackFunc {
	return func(keyid []byte, usage string, marshalledKey []byte) error {
		// Write key to file in keyDir
		err := ioutil.WriteFile(path.Join(keyDir, fmt.Sprintf("%x.pubkey", keyid)), marshalledKey, 0600)
		if err != nil {
			return err
		}
		return nil
	}
}

// loadKeysFromDir returns a callback that loads keys from a directory
func loadKeysFromDir(keyDir string) keypool.LoadKeysCallbackFunc {
	return func(keypool *keypool.KeyPool) error {
		files, err := ioutil.ReadDir(keyDir)
		if err != nil {
			return err
		}
		for _, file := range files {
			d, err := ioutil.ReadFile(path.Join(keyDir, file.Name()))
			if err != nil {
				return err
			}
			loadKey, err := new(signkeys.PublicKey).Unmarshal(d)
			if err != nil {
				return err
			}
			keypool.LoadKey(loadKey) // ignore errors
		}
		return nil
	}
}
