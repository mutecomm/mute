package nilstore

import (
	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/util/times"
)

// NilStore is a walletstore without abilities
type NilStore struct {
	AuthToken      []byte
	AuthTokenTries int
	LastToken      *client.TokenEntry
	VerifyKeys     [][ed25519.PublicKeySize]byte
}

// SetAuthToken without persistance
func (ns *NilStore) SetAuthToken(authToken []byte, tries int) error {
	ns.AuthToken = authToken
	ns.AuthTokenTries = tries
	// spew.Dump(ns.AuthToken)
	return nil
}

// GetAuthToken without persistance
func (ns *NilStore) GetAuthToken() (authToken []byte, tries int) {
	return ns.AuthToken, ns.AuthTokenTries
}

// SetToken without persistance
func (ns *NilStore) SetToken(tokenEntry client.TokenEntry) error {
	ns.LastToken = &tokenEntry
	// fmt.Printf("Token: %+v\n", ns.LastToken)
	// spew.Dump(ns.LastToken)
	return nil
}

// GetToken without persistance
func (ns *NilStore) GetToken(tokenHash []byte, lockID int64) (tokenEntry *client.TokenEntry, err error) {
	return ns.LastToken, nil
}

// SetVerifyKeys without persistance
func (ns *NilStore) SetVerifyKeys(keys [][ed25519.PublicKeySize]byte) {
	ns.VerifyKeys = keys
	// fmt.Printf("VerifyKeys: %+v\n", ns.VerifyKeys)
	// spew.Dump(ns.VerifyKeys)
}

// GetVerifyKeys without persistance
func (ns *NilStore) GetVerifyKeys() [][ed25519.PublicKeySize]byte {
	return ns.VerifyKeys
}

// DelToken without function
func (ns *NilStore) DelToken(tokenHash []byte) {}

// LockToken without function
func (ns *NilStore) LockToken(tokenHash []byte) int64 {
	return times.NowNano()
}

// UnlockToken without function
func (ns *NilStore) UnlockToken(tokenHash []byte) {}

// GetAndLockToken without persistance
func (ns *NilStore) GetAndLockToken(usage string, owner *[ed25519.PublicKeySize]byte) (*client.TokenEntry, error) {
	return ns.LastToken, nil
}

// FindToken without persistance
func (ns *NilStore) FindToken(usage string) (*client.TokenEntry, error) {
	return ns.LastToken, nil
}

// GetExpire without function
func (ns *NilStore) GetExpire() []byte {
	return nil
}

//GetInReissue without function
func (ns *NilStore) GetInReissue() []byte {
	return nil
}

//GetBalanceOwn without function
func (ns *NilStore) GetBalanceOwn(usage string) int64 {
	return 0
}

//GetBalance without function
func (ns *NilStore) GetBalance(usage string, owner *[ed25519.PublicKeySize]byte) int64 {
	return 0
}

// ExpireUnusable without function
func (ns *NilStore) ExpireUnusable() bool {
	return false
}
