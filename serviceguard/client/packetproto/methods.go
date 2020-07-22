// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packetproto

import (
	"errors"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/mutecomm/mute/serviceguard/common/token"
	"github.com/mutecomm/mute/serviceguard/common/types"
	"github.com/ronperry/cryptoedge/genericblinding"
	"github.com/ronperry/cryptoedge/jjm"
)

var (
	// ErrNoToken signals a problem with token creation
	ErrNoToken = errors.New("client: token creation failed")
	// ErrMissingSigner signals that a request must be signed but no signer is present
	ErrMissingSigner = errors.New("client: signer missing but required")
	// ErrParamMismatch signals that a token and parameters do not match
	ErrParamMismatch = errors.New("client: parameters do not match token")
)

var zeroOwner = [ed25519.PublicKeySize]byte{0x00}

// NewToken returns a blinded token ready for signing. Blindmessage goes to server, blindfactors and clear message remain local
func (c Client) NewToken(issuerPubKey *signkeys.PublicKey, pubParams *jjm.BlindingParamClient, owner *[ed25519.PublicKeySize]byte) (genericblinding.BlindingFactors, genericblinding.BlindMessage, *token.Token, error) {
	newToken := token.New(&issuerPubKey.KeyID, owner)
	if newToken == nil {
		return nil, nil, nil, ErrNoToken
	}
	blindClient := jjm.NewGenericBlindingClient(&issuerPubKey.PublicKey, c.Curve)
	clearMessage := jjm.NewClearMessage(newToken.Hash())
	blindingParams := jjm.NewBlindingParamClient(&issuerPubKey.PublicKey)
	blindingParams.PointRs1 = pubParams.PointRs1
	blindingParams.PointRs2 = pubParams.PointRs2
	blindingParams.ScalarLs1 = pubParams.ScalarLs1
	blindingParams.ScalarLs2 = pubParams.ScalarLs2
	blindFactors, blindMessage, err := blindClient.Blind(blindingParams, clearMessage)
	if err != nil {
		return nil, nil, nil, err
	}
	return blindMessage, blindFactors, newToken, err
}

// Reissue creates a request to be sent to the server to reissue a new token for an old token. oldOwner is the Private key for whoever owned oldToken.
// NewOwner is the public key for whoever is to own the new token. Both can be nil.
func (c Client) Reissue(oldTokenEnc []byte, oldOwner *[ed25519.PrivateKeySize]byte, newOwner *[ed25519.PublicKeySize]byte, params []byte) (toServer []byte, storeLocal *types.ReissuePacketPrivate, err error) {
	packet := new(types.ReissuePacket)
	packet.CallType = types.CallTypeReissue
	oldToken, err := token.Unmarshal(oldTokenEnc)
	if err != nil {
		return nil, nil, err
	}
	// Get info from parameters
	pubKey, pubParams, _, canReissue, err := types.UnmarshalParams(params)
	if err != nil {
		return nil, nil, err
	}
	// Verify that oldToken and params match
	oldKeyID := new([signkeys.KeyIDSize]byte)
	copy(oldKeyID[:], oldToken.KeyID)
	oldPubKey, err := c.Keypool.Lookup(*oldKeyID)
	if err != nil {
		return nil, nil, err
	}
	// Verify usage
	if oldPubKey.Usage != pubKey.Usage {
		return nil, nil, ErrParamMismatch
	}
	// Verify same service-guard
	if oldPubKey.Signer != pubKey.Signer {
		return nil, nil, ErrParamMismatch
	}
	// Add parameter publickey to keypool
	saveID, err := c.Keypool.LoadKey(pubKey)
	if err != nil && err != keypool.ErrExists {
		return nil, nil, err
	}
	// Save key to permanent storage
	if err == nil {
		c.Keypool.SaveKey(*saveID)
	}
	// Create new token data
	blindMessage, blindFactors, newToken, err := c.NewToken(pubKey, pubParams, newOwner)
	if err != nil {
		return nil, nil, err
	}
	packet.Token, err = oldToken.Marshal()
	if err != nil {
		return nil, nil, err
	}
	packet.BlindToken, err = blindMessage.Marshal()
	if err != nil {
		return nil, nil, err
	}
	packet.Params = params
	_, owner := oldToken.Properties()
	if owner != nil {
		if oldOwner == nil {
			return nil, nil, ErrMissingSigner
		}
	}
	packet.Sign(oldOwner)
	rpacket, err := packet.Marshal()
	if err != nil {
		return nil, nil, err
	}
	local := new(types.ReissuePacketPrivate)
	local.CanReissue = canReissue
	local.PublicKey, err = pubKey.Marshal()
	if err != nil {
		return nil, nil, err
	}
	local.Factors, err = blindFactors.Marshal()
	if err != nil {
		return nil, nil, err
	}
	local.Token, err = newToken.Marshal()
	if err != nil {
		return nil, nil, err
	}
	rhash := packet.Hash()
	local.RequestHash = rhash[:]
	local.Request = rpacket

	return rpacket, local, nil
}

// Unblind a signature and convert it into a token
func (c Client) Unblind(storeLocal *types.ReissuePacketPrivate, signature []byte) ([]byte, error) {
	pubkey, err := new(signkeys.PublicKey).Unmarshal(storeLocal.PublicKey)
	if err != nil {
		return nil, err
	}
	params, err := jjm.NewBlindingFactors(&pubkey.PublicKey).Unmarshal(storeLocal.Factors)
	if err != nil {
		return nil, err
	}
	token, err := token.Unmarshal(storeLocal.Token)
	if err != nil {
		return nil, err
	}
	clearMessage := jjm.NewClearMessage(token.Hash())
	blindSig, err := jjm.NewBlindSignature(&pubkey.PublicKey).Unmarshal(signature)
	blindClient := jjm.NewGenericBlindingClient(&pubkey.PublicKey, c.Curve)
	sig, _, err := blindClient.Unblind(params, clearMessage, blindSig)
	if err != nil {
		return nil, err
	}
	_, err = blindClient.Verify(sig, clearMessage)
	if err != nil {
		return nil, err
	}
	t := sig.(jjm.ClearSignature)
	token.AddSignature(&t)
	return token.Marshal()
}

// Spend creates a spend packet
func (c Client) Spend(token []byte, owner *[ed25519.PrivateKeySize]byte) ([]byte, error) {
	packet := new(types.SpendPacket)
	packet.CallType = types.CallTypeSpend
	packet.Token = token
	packet.Sign(owner)
	return packet.Marshal()
}
