// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package walletrpc implements calls to the walletserver
package walletrpc

import (
	"encoding/base64"
	"errors"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/constants"
	"github.com/mutecomm/mute/serviceguard/common/walletauth"
	"github.com/mutecomm/mute/util/jsonclient"
)

var (
	// ErrParams is returned if a call returned bad parameters
	ErrParams = errors.New("walletrpc: Bad RPC parameters")
)

// DefaultClientFactory is the default factory for new clients
var DefaultClientFactory = jsonclient.New

// ServiceURL is the default URL for the wallet service
var ServiceURL = constants.WalletServerURL

// WalletClient implements a wallet service client
type WalletClient struct {
	ClientFactory   func(string, []byte) (*jsonclient.URLClient, error)
	ServiceGuardCA  []byte                        // The CA of the serviceguard, if any
	PubKey          *[ed25519.PublicKeySize]byte  // Public key of client
	PrivKey         *[ed25519.PrivateKeySize]byte // Private key of PrivKey
	LastAuthCounter uint64                        // Last authentication counter
	LastAuthToken   []byte                        // Last authtoken used, required for call caching
}

// New returns a new walletservice  client
func New(pubKey *[ed25519.PublicKeySize]byte, PrivKey *[ed25519.PrivateKeySize]byte, cacert []byte) *WalletClient {
	wc := new(WalletClient)
	wc.ServiceGuardCA = cacert
	wc.ClientFactory = DefaultClientFactory
	wc.PubKey = pubKey
	wc.PrivKey = PrivKey
	return wc
}

// GetBalance inquires the wallet service for the client's balance. It tries to escape replay errors.
func (wc *WalletClient) GetBalance() (SubscriptionTokens, PrepayTokens, LastSubscribeLoad uint64, err error) {
	lastcounter := wc.LastAuthCounter
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		authtoken := wc.LastAuthToken
		if authtoken == nil {
			authtoken = walletauth.CreateToken(wc.PubKey, wc.PrivKey, lastcounter+1)
		}
		SubscriptionTokens, PrepayTokens, LastSubscribeLoad, lastcounter, err = wc.getBalance(authtoken)
		if err == walletauth.ErrReplay {
			wc.LastAuthCounter = lastcounter
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		if err != nil {
			wc.LastAuthToken = authtoken
		}
		break CallLoop
	}
	return SubscriptionTokens, PrepayTokens, LastSubscribeLoad, err
}

// getBalance is the real GetBalance call to return the client's balance from the wallet service
func (wc WalletClient) getBalance(authtoken []byte) (SubscriptionTokens, PrepayTokens, LastSubscribeLoad, LastCounter uint64, err error) {
	var ok bool
	var SubscriptionTokensT, PrepayTokensT, LastSubscribeLoadT float64
	method := "WalletServer.GetBalance"
	client, err := wc.ClientFactory(ServiceURL, wc.ServiceGuardCA)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	data, err := client.JSONRPCRequest(method, struct{ AuthToken string }{AuthToken: authtokenEnc})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return 0, 0, 0, LastCounter, err
	}
	if _, ok := data["SubscriptionTokens"]; !ok {
		return 0, 0, 0, 0, ErrParams
	}

	if SubscriptionTokensT, ok = data["SubscriptionTokens"].(float64); !ok {
		return 0, 0, 0, 0, ErrParams
	}
	SubscriptionTokens = uint64(SubscriptionTokensT)
	if _, ok := data["PrepayTokens"]; !ok {
		return 0, 0, 0, 0, ErrParams
	}
	if PrepayTokensT, ok = data["PrepayTokens"].(float64); !ok {
		return 0, 0, 0, 0, ErrParams
	}
	PrepayTokens = uint64(PrepayTokensT)
	if _, ok := data["LastSubscribeLoad"]; !ok {
		return 0, 0, 0, 0, ErrParams
	}
	if LastSubscribeLoadT, ok = data["LastSubscribeLoad"].(float64); !ok {
		return 0, 0, 0, 0, ErrParams
	}
	LastSubscribeLoad = uint64(LastSubscribeLoadT)
	return SubscriptionTokens, PrepayTokens, LastSubscribeLoad, 0, nil
}

// GetToken gets a token for usage from the wallet service.
func (wc *WalletClient) GetToken(usage string) (token, params, pubKeyUsed []byte, err error) {
	lastcounter := wc.LastAuthCounter
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		authtoken := wc.LastAuthToken
		if authtoken == nil {
			authtoken = walletauth.CreateToken(wc.PubKey, wc.PrivKey, lastcounter+1)
		}
		token, params, pubKeyUsed, lastcounter, err = wc.getToken(usage, authtoken)
		if err == walletauth.ErrReplay {
			wc.LastAuthCounter = lastcounter
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		if err != nil {
			wc.LastAuthToken = authtoken
		}
		break CallLoop
	}
	return token, params, pubKeyUsed, err
}

func (wc WalletClient) getToken(usage string, authtoken []byte) (token, params, pubKeyUsed []byte, LastCounter uint64, err error) {
	method := "WalletServer.GetToken"
	client, err := wc.ClientFactory(ServiceURL, wc.ServiceGuardCA)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	data, err := client.JSONRPCRequest(method, struct{ AuthToken, Usage string }{AuthToken: authtokenEnc, Usage: usage})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return nil, nil, nil, LastCounter, err
	}
	if _, ok := data["Token"]; !ok {
		return nil, nil, nil, 0, ErrParams
	}
	if _, ok := data["Token"].(string); !ok {
		return nil, nil, nil, 0, ErrParams
	}
	if _, ok := data["Params"]; !ok {
		return nil, nil, nil, 0, ErrParams
	}
	if _, ok := data["Params"].(string); !ok {
		return nil, nil, nil, 0, ErrParams
	}
	token, err = base64.StdEncoding.DecodeString(data["Token"].(string))
	if err != nil {
		return nil, nil, nil, 0, ErrParams
	}
	params, err = base64.StdEncoding.DecodeString(data["Params"].(string))
	if err != nil {
		return nil, nil, nil, 0, ErrParams
	}
	pubKeyUsed, err = base64.StdEncoding.DecodeString(data["PubKeyUsed"].(string))
	if err != nil {
		return nil, nil, nil, 0, ErrParams
	}

	return token, params, pubKeyUsed, 0, nil
}
