// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"github.com/agl/ed25519"
)

// WalletStore interface for storing and fetching wallet state.
type WalletStore interface {
	SetAuthToken(authToken []byte, tries int) error                                        // Store an authtoken and tries
	GetAuthToken() (authToken []byte, tries int)                                           // Get authtoken from store
	SetToken(tokenEntry TokenEntry) error                                                  // SetToken writes a token to the walletstore. repeated calls update the entry of tokenEntry.Hash is the same
	GetToken(tokenHash []byte, lockID int64) (*TokenEntry, error)                          // GetToken returns the token identified by tokenHash. If lockID>=0, enforce lock (return ErrLocked)
	GetAndLockToken(usage string, owner *[ed25519.PublicKeySize]byte) (*TokenEntry, error) // Return a token matching usage and optional owner. Must return ErrNoToken if no token is in store
	FindToken(usage string) (*TokenEntry, error)                                           // Find a token owner by self that has usage set
	DelToken(tokenHash []byte)                                                             // DelToken deletes the token identified by tokenHash
	LockToken(tokenHash []byte) (LockID int64)                                             // Lock token against other use. Return lockID > 0 on success, <0 on failure
	UnlockToken(tokenHash []byte)                                                          // Unlock a locked token
	SetVerifyKeys([][ed25519.PublicKeySize]byte)                                           // Save verification keys
	GetVerifyKeys() [][ed25519.PublicKeySize]byte                                          // Load verification keys. Offline only
	GetExpire() (tokenHash []byte)                                                         // Return next expiring token that can be reissued, or nil
	GetInReissue() (tokenHash []byte)                                                      // Get next token with interrupted reissue
	GetBalanceOwn(usage string) int64                                                      // Get the number of tokens for usage owned by self
	GetBalance(usage string, owner *[ed25519.PublicKeySize]byte) int64                     // Get the number of tokens for usage owner by owner, or by anybody but myself if owner==nil
	ExpireUnusable() bool                                                                  // Expire unusable tokens, returns true if it should be called again
}

// TokenEntry is an entry in the token database.
type TokenEntry struct {
	Hash            []byte                        // The unique token identifier
	Token           []byte                        // The token itself, marshalled
	Params          []byte                        // Params for the token, can be nil
	OwnerPubKey     *[ed25519.PublicKeySize]byte  // The Owner of the token
	OwnerPrivKey    *[ed25519.PrivateKeySize]byte // The private key of the owner, can be nil if specified for somebody else
	Renewable       bool                          // The token can be renewed (at least once)
	CanReissue      bool                          // Can this token be reissued?
	Usage           string                        // Usage of the token
	Expire          int64                         // When the token will expire
	ServerPacket    []byte                        // Packet to be send to server
	BlindingFactors []byte                        // Local blinding factors
	NewOwnerPubKey  *[ed25519.PublicKeySize]byte  // The Owner of the token after reissue
	NewOwnerPrivKey *[ed25519.PrivateKeySize]byte // The private key of the new owner, can be nil if specified for somebody else
}
