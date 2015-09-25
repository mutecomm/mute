package client

import (
	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/client/walletrpc"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/serviceguard/common/token"
	"github.com/mutecomm/mute/serviceguard/common/types"
)

// WalletToken gets a token from wallet that matches usage.
// The token is reissued for owner if not nil.
// If the token is a subscription-token and owner is not present, it
// is stored and a "NeedReissue" error is returned.
func (c *Client) WalletToken(usage string, owner *[ed25519.PublicKeySize]byte) (tokenHash []byte, err error) {
	newToken, params, pubkeyUsed, err := c.getTokenFromWallet(usage)
	if err != nil {
		return nil, err
	}
	// Cache token, params
	tokenUnmarshalled, err := token.Unmarshal(newToken)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	// Parse pubkeyUsed and add to keypool
	signerPubKey, err := new(signkeys.PublicKey).Unmarshal(pubkeyUsed)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	keyid, err := c.packetClient.Keypool.LoadKey(signerPubKey)
	if err != nil && err != keypool.ErrExists {
		c.LastError = err
		return nil, ErrFatal
	}
	c.packetClient.Keypool.SaveKey(*keyid)
	// If we have params this is not renewable
	renewable := false
	if params == nil {
		renewable = true
	} else {
		// Unless the params state otherwise....
		_, _, _, canReissue, err := types.UnmarshalParams(params)
		if err != nil {
			c.LastError = err
			return nil, ErrFatal
		}
		if canReissue {
			renewable = true
		}
	}
	//tokenUnmarshalled.KeyID
	ownerPubkey, ownerPrivkey := splitKey(c.walletKey)
	// Set tokenentry struct for storage
	tokenentry := TokenEntry{
		Hash:         tokenUnmarshalled.Hash(),
		Token:        newToken,
		Params:       params,
		OwnerPubKey:  ownerPubkey,
		OwnerPrivKey: ownerPrivkey,
		Renewable:    renewable,
		CanReissue:   true,
		Usage:        signerPubKey.Usage,
		Expire:       signerPubKey.Expire,
	}
	err = c.walletStore.SetToken(tokenentry) // Cache current state
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	if owner == nil && renewable == false {
		return tokenentry.Hash, ErrNeedReissue
	}
	// Reissue
	return c.ReissueToken(tokenentry.Hash, owner)
}

// getTokenFromWallet gets a single token for usage from Wallet.
func (c *Client) getTokenFromWallet(usage string) (token, params, pubkeyUsed []byte, err error) {
	var tries int
	if !c.IsOnline() {
		c.LastError = ErrOffline
		return nil, nil, nil, ErrOffline
	}
	onlineGroup.Add(1)
	defer onlineGroup.Done()
	pubkey, privkey := splitKey(c.walletKey)
	if c.walletRPC == nil {
		c.walletRPC = walletrpc.New(pubkey, privkey, c.cacert)
	}
	// lookup cached authtoken, set
	c.walletRPC.LastAuthToken, tries = c.walletStore.GetAuthToken()
	if tries > AuthTokenRetry {
		c.walletRPC.LastAuthToken = nil
		tries = 0
	}
	newToken, params, pubkeyUsed, err := c.walletRPC.GetToken(usage)
	if err != nil {
		c.LastError = err
		_, fatal, err := lookupError(err)
		if fatal {
			c.LastError = err
			return nil, nil, nil, ErrFinal
		}
		// cache walletClient.LastAuthToken
		err = c.walletStore.SetAuthToken(c.walletRPC.LastAuthToken, tries+1)
		if err != nil {
			c.LastError = err
			return nil, nil, nil, ErrFatal
		}
		return nil, nil, nil, ErrRetry
	}
	// Reset authtoken cache
	c.walletStore.SetAuthToken(nil, 0)
	return newToken, params, pubkeyUsed, nil
}
