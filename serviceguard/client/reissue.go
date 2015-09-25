package client

import (
	"crypto/rand"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/client/guardrpc"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/serviceguard/common/token"
	"github.com/mutecomm/mute/serviceguard/common/types"
)

// ReissueToken reissues a token identified by tokenHash for owner.
func (c *Client) ReissueToken(tokenHash []byte, ownerPubkey *[ed25519.PublicKeySize]byte) (newTokenHash []byte, err error) {
	var ownerPrivkey *[ed25519.PrivateKeySize]byte
	if !c.IsOnline() {
		c.LastError = ErrOffline
		return nil, ErrOffline
	}
	onlineGroup.Add(1)
	defer onlineGroup.Done()
	// Lock token against other use
	lockID := c.LockToken(tokenHash)
	if lockID == 0 {
		c.LastError = ErrLocked
		return nil, ErrRetry
	}
	defer c.UnlockToken(tokenHash)
	// Get client and token data
	issueClient, err := guardrpc.New(c.cacert)
	if err != nil {
		c.LastError = err
		return nil, ErrRetry
	}
	tokenEntry, err := c.walletStore.GetToken(tokenHash, lockID)
	if err != nil {
		c.LastError = err
		if err == ErrLocked {
			return nil, ErrRetry
		}
		return nil, ErrFatal
	}
	if tokenEntry.OwnerPrivKey == nil {
		c.LastError = ErrNotMine
		return nil, ErrFatal
	}
	tokenUnmarshalled, err := token.Unmarshal(tokenEntry.Token)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	keyid, _ := tokenUnmarshalled.Properties()
	key, err := c.packetClient.Keypool.Lookup(*keyid)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	// Test if we are communicating already
	if tokenEntry.ServerPacket == nil {
		// Test if we have params
		if tokenEntry.Params == nil {
			params, err := issueClient.GetParams(&key.Signer)
			if err != nil {
				c.LastError = err
				_, fatal, err := lookupError(err)
				if fatal {
					c.LastError = err
					return nil, ErrFinal
				}
				return nil, ErrRetry
			}
			tokenEntry.Params = params
			err = c.walletStore.SetToken(*tokenEntry)
			if err != nil {
				c.LastError = err
				return nil, ErrFatal
			}
		}
		// Generate new owner if no owner is specified
		if ownerPubkey == nil {
			ownerPubkey, ownerPrivkey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				c.LastError = err
				return nil, ErrFatal
			}
			tokenEntry.NewOwnerPrivKey = ownerPrivkey
		}
		tokenEntry.NewOwnerPubKey = ownerPubkey
		// Generate blinding packet
		serverPacket, blindingFactors, err := c.packetClient.Reissue(tokenEntry.Token, tokenEntry.OwnerPrivKey, tokenEntry.NewOwnerPubKey, tokenEntry.Params)
		if err != nil {
			c.LastError = err
			return nil, ErrFatal
		}
		// Marshall local, store packet and local in walletStore
		tokenEntry.BlindingFactors, err = blindingFactors.Marshal()
		if err != nil {
			c.LastError = err
			return nil, ErrFatal
		}
		tokenEntry.ServerPacket = serverPacket
		err = c.walletStore.SetToken(*tokenEntry)
		if err != nil {
			c.LastError = err
			return nil, ErrFatal
		}
	}
	// We have everything, make the call
	replyPacket, newPubkey, err := issueClient.Reissue(&key.Signer, tokenEntry.ServerPacket)
	if err != nil {
		c.LastError = err
		_, fatal, err := lookupError(err)
		if fatal {
			c.LastError = err
			return nil, ErrFinal
		}
		return nil, ErrRetry
	}
	c.walletStore.DelToken(tokenEntry.Hash) // Delete old token, it's invalid from here
	// Parse new pubkey and add to keypool
	signerPubKey, err := new(signkeys.PublicKey).Unmarshal(newPubkey)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	keyid, err = c.packetClient.Keypool.LoadKey(signerPubKey)
	if err != nil && err != keypool.ErrExists {
		c.LastError = err
		return nil, ErrFatal
	}
	c.packetClient.Keypool.SaveKey(*keyid)
	// Unblind the new token
	blindingFactors, err := new(types.ReissuePacketPrivate).Unmarshal(tokenEntry.BlindingFactors)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	newToken, err := c.packetClient.Unblind(blindingFactors, replyPacket)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	// Write it to database
	tokenUnmarshalled, err = token.Unmarshal(newToken)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	keyid, _ = tokenUnmarshalled.Properties()
	signerPubKey, err = c.packetClient.Keypool.Lookup(*keyid)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	tokenentryNew := TokenEntry{
		Hash:         tokenUnmarshalled.Hash(),
		Token:        newToken,
		Params:       nil,
		OwnerPubKey:  tokenEntry.NewOwnerPubKey,
		OwnerPrivKey: tokenEntry.NewOwnerPrivKey,
		Renewable:    tokenEntry.Renewable,
		CanReissue:   tokenEntry.Renewable,
		Usage:        signerPubKey.Usage,
		Expire:       signerPubKey.Expire,
	}
	err = c.walletStore.SetToken(tokenentryNew)
	if err != nil {
		c.LastError = err
		return nil, ErrFatal
	}
	return tokenentryNew.Hash, nil
}
