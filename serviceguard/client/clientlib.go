// Package client implements a serviceguard client with wallet backend. It offers methods to
// fetch tokens from the walletserver, reissue tokens for use with services and receive tokens as a service.
// It furthermore implements functions for wallet housekeeping.
// Wallet methods will return ErrRetry if the error is recoverable at a later time, ErrFatal if an internal (client-side)
// error exists - such as unavailable processing or storage. ErrFinal will be returned if an error is not
// recoverable but not due to a system/service error. ErrOffline is returned if a function can only be run if it
// has internet access. Details on what exactly caused an error is available in client.LastError.
package client

import (
	"sync"

	"github.com/agl/ed25519"
	keylookupClient "github.com/mutecomm/mute/serviceguard/client/keylookup"
	"github.com/mutecomm/mute/serviceguard/client/packetproto"
	"github.com/mutecomm/mute/serviceguard/client/walletrpc"
	"github.com/mutecomm/mute/serviceguard/common/constants"
	"github.com/mutecomm/mute/serviceguard/common/types"
)

// AuthTokenRetry defines how often an AuthToken should be retried on
// connection/server errors.
var AuthTokenRetry = constants.AuthTokenRetry

// TrustRoot is the signature key of the key lookup service.
// It should be globally the same, always.
var TrustRoot *[ed25519.PublicKeySize]byte

// synchronize token lock calls
var tokenLock = new(sync.Mutex)

// runnerLock synchronizes runner activity
var runnerLock = new(sync.Mutex)

// wait for online routines
var onlineGroup = new(sync.WaitGroup)

// Target defines a fill target for the wallet.
type Target struct {
	Usage         string
	LowWaterMark  int64
	HighWaterMark int64
	balance       int64
}

// Client encapsulates a client API.
type Client struct {
	online        bool
	walletKey     *[ed25519.PrivateKeySize]byte
	cacert        []byte
	walletStore   WalletStore
	walletRPC     *walletrpc.WalletClient
	packetClient  *packetproto.Client
	LastError     error
	runnerRunning bool
	target        map[[ed25519.PublicKeySize]byte]Target
	stopChan      chan bool
}

// New returns a new client. In most cases, use mute/serviceguard/client/trivial instead
func New(keyBackends []types.Backend, walletstore WalletStore, walletKey *[ed25519.PrivateKeySize]byte, cacert []byte) (*Client, error) {
	var err error
	c := new(Client)
	c.packetClient, err = packetproto.New(keyBackends)
	if err != nil {
		return nil, err
	}
	err = c.packetClient.Keypool.Load()
	if err != nil {
		return nil, err
	}
	c.walletStore = walletstore
	c.cacert = cacert
	c.walletKey = walletKey
	c.stopChan = make(chan bool)
	pubkey, privkey := splitKey(c.walletKey)
	c.walletRPC = walletrpc.New(pubkey, privkey, c.cacert)
	return c, nil
}

// IsOnline tests if the client is online.
func (c *Client) IsOnline() bool {
	return c.online
}

// GoOnline sets the client online.
func (c *Client) GoOnline() {
	c.GetVerifyKeys()
	c.online = true
}

// GoOffline sets the client offline. The method will block until all routines
// using the internet connection have returned.
func (c *Client) GoOffline() {
	c.online = false
	go c.StopRunner()
	onlineGroup.Wait()
}

// LockToken locks a token against use by others.
func (c *Client) LockToken(tokenHash []byte) int64 {
	tokenLock.Lock()
	defer tokenLock.Unlock()
	return c.walletStore.LockToken(tokenHash)
}

// UnlockToken unlocks a previously locked token.
func (c *Client) UnlockToken(tokenHash []byte) {
	c.walletStore.UnlockToken(tokenHash)
}

// splitKey splits the wallet private key into public and private key.
func splitKey(privkey *[ed25519.PrivateKeySize]byte) (*[ed25519.PublicKeySize]byte, *[ed25519.PrivateKeySize]byte) {
	var pubkey [ed25519.PublicKeySize]byte
	copy(pubkey[:], privkey[ed25519.PrivateKeySize-ed25519.PublicKeySize:])
	return &pubkey, privkey
}

// GetVerifyKeys loads the verification keys from the keylookup server and
// adds them to the keypool and wallet.
func (c *Client) GetVerifyKeys() error {
	var verifyKeys [][ed25519.PublicKeySize]byte
	var err error
	if c.online {
		onlineGroup.Add(1)
		defer onlineGroup.Done()
		// Online!!! Load from keylookup service
		lookupClient := keylookupClient.New(nil, c.cacert, TrustRoot)
		verifyKeys, err = lookupClient.GetVerifyList()
		if err != nil {
			c.LastError = err
			err = ErrRetry
		}
		if verifyKeys != nil {
			c.walletStore.SetVerifyKeys(verifyKeys)
		}
	}
	if verifyKeys == nil {
		// We need keys anyways
		verifyKeys = c.walletStore.GetVerifyKeys()
	}
	for _, vKey := range verifyKeys {
		c.packetClient.AddVerifyKey(&vKey)
	}
	return err
}

// GetToken returns a token from the database matching usage and optional owner. The token
// will be locked and must be deleted with DelToken when used (or unlocked).
// It should be used like this:
// 		func DoWithToken() (retErr error){
//			token, err := client.GetToken(usage, owner)
//			defer func(){
//				if retErr == nil{
//					client.DelToken(token.Hash)
//				} else {
//					client.UnlockToken(token.Hash)
//				}
//			}
//			... do something here that could fail
//		}
func (c *Client) GetToken(usage string, owner *[ed25519.PublicKeySize]byte) (*TokenEntry, error) {
	// Check if we have a matching token already
	retToken, err := c.walletStore.GetAndLockToken(usage, owner)
	if err == ErrNoToken {
		var tokenHash []byte
		if owner == nil { // We can only get new tokens if we know the recipient
			return nil, ErrNeedReissue
		}
		// First, check if we have a token that can be repossessed
		tokenReissue, err := c.walletStore.FindToken(usage)
		if err != nil {
			// No... Get a new token from the walletserver
			tokenHash, err = c.WalletToken(usage, owner)
			if err != nil {
				return nil, err
			}
		} else {
			// Yes... reissue to the new owner
			tokenHash, err = c.ReissueToken(tokenReissue.Hash, owner)
			if err != nil {
				return nil, err
			}
		}
		// Lock token, get token. It can fail on race, requiring retry
		lockID := c.LockToken(tokenHash)
		if lockID <= 0 {
			c.LastError = ErrLocked
			return nil, ErrRetry
		}
		retToken, err = c.walletStore.GetToken(tokenHash, lockID)
		if err != nil {
			c.LastError = err
			return nil, ErrFatal
		}
	}
	return retToken, nil
}

// DelToken deletes a token.
func (c *Client) DelToken(tokenHash []byte) {
	c.walletStore.DelToken(tokenHash)
}

// GetBalanceOwn returns the number of renewable tokens for usage.
func (c *Client) GetBalanceOwn(usage string) int64 {
	return c.walletStore.GetBalanceOwn(usage)
}

// GetBalance returns the number of usable tokens available for usage owned by
// owner or not self (if owner==nil).
func (c *Client) GetBalance(usage string, owner *[ed25519.PublicKeySize]byte) int64 {
	return c.walletStore.GetBalance(usage, owner)
}

// SetTarget sets the fill target of the wallet. The map contains the public
// key of the receiver and the usage/watermark definition.
func (c *Client) SetTarget(target map[[ed25519.PublicKeySize]byte]Target) {
	runnerLock.Lock()
	defer runnerLock.Unlock()
	c.target = target
}
