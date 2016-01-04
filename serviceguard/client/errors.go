// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
	"sync"
)

type errorTranslation struct {
	err   error
	fatal bool
}

var errorTranslateMap map[string]errorTranslation
var errorTranslateMutex *sync.Mutex

func registerTranslateError(errorString string, fatal bool) error {
	if errorTranslateMap == nil {
		errorTranslateMap = make(map[string]errorTranslation)
		errorTranslateMutex = new(sync.Mutex)
	}
	e := errorTranslation{
		err:   errors.New(errorString),
		fatal: fatal,
	}

	errorTranslateMap[errorString] = e
	return e.err
}

func lookupError(inputError error) (translated, fatal bool, err error) {
	errorTranslateMutex.Lock()
	defer errorTranslateMutex.Unlock()
	str := string(inputError.Error())
	if e, ok := errorTranslateMap[str]; ok {
		return true, e.fatal, e.err
	}
	return false, false, inputError
}

func translateError(inputError error) error {
	_, _, err := lookupError(inputError)
	return err
}

var (
	// Errors produced by the client

	// ErrRetry is returned on recoverable errors
	ErrRetry = errors.New("client: retry")
	// ErrOffline is returned if the client is offline
	ErrOffline = errors.New("client: offline")
	// ErrFinal is returned on final errors that cannot continue
	ErrFinal = errors.New("client: final serviceguard error")
	// ErrFatal is returned on fatal errors produced by the client implementation itself
	ErrFatal = errors.New("client: fatal client error")
	// ErrNeedReissue is returned if a non-renewable token was issued by the walletserver but not owner was specified
	ErrNeedReissue = errors.New("client: token needs reissue to owner")
	// ErrNotMine is returned if a token is not under our control
	ErrNotMine = errors.New("client: not my token")
	// ErrLocked is returned if a token has been locked
	ErrLocked = errors.New("client: token in use")
	// ErrExpireToken is returned if a token has expired
	ErrExpireToken = errors.New("client: token expired")
	// ErrSignatureToken is returned if the token has a bad signature
	ErrSignatureToken = errors.New("client: bad signature")
	// ErrOwnerToken is returned if a token has an unexpected owner
	ErrOwnerToken = errors.New("client: unexpected owner")
	// ErrUsageToken is returned if a token has an unexpected usage
	ErrUsageToken = errors.New("client: unexpected usage")
	// ErrTokenKnown is returned if a received token is already known
	ErrTokenKnown = errors.New("client: token is already known")
	// ErrNoToken is returned if no token could be fetched from wallet storage
	ErrNoToken = errors.New("client: no token in wallet")
)

var (
	// Errors from wallet server:

	// ErrWalletServer is returned if the server experienced a problem that cannot be exposed to the client
	ErrWalletServer = registerTranslateError("walletserver: server error", false)
	// ErrNoUser is returned if the user could not be found
	ErrNoUser = registerTranslateError("walletserver: no such user", true)
	// ErrBadToken is returned if the user's authtoken could not be verified
	ErrBadToken = registerTranslateError("walletserver: bad token", true)
	// ErrInsufficientFunds is returned if the user's funds are exhausted
	ErrInsufficientFunds = registerTranslateError("walletserver: insufficient funds", true)

	//
	// Errors from keylookup server:

	// ErrKeyLookupServer is returned if there was an error in the lookup server
	ErrKeyLookupServer = registerTranslateError("keylookup: server error", false)
	// ErrNotFound is returned if the key could not be found
	ErrNotFound = registerTranslateError("keylookup: key not found", true)

	//
	// Errors from issuer server:

	// ErrUsageMismatch is returned if the usage of the parameter publickey and the token publickey do not match
	ErrUsageMismatch = registerTranslateError("issuer: parameter and Token usage mismatch", true)
	// ErrParamsExpired is returned if the parameters given are not in line with any available private key
	ErrParamsExpired = registerTranslateError("issuer: parameters have expired", true)
	// ErrBadCallType is returned if a wrong calltype is present in a packet
	ErrBadCallType = registerTranslateError("issuer: wrong calltype", true)
	// ErrIssuerServer is returned on server error
	ErrIssuerServer = registerTranslateError("issuer: server errror", false)
	// ErrTokenDoubleSpend is returned if the token has already been spent
	ErrTokenDoubleSpend = registerTranslateError("issuer: token double spend", true)
	// ErrParamDoubleSpend is returned if a parameter has already been spent
	ErrParamDoubleSpend = registerTranslateError("issuer: parameter double spend", true)
	// ErrBadPacket is returned if packet contents cannot be unmarshalled
	ErrBadPacket = registerTranslateError("issuer: bad package", true)
	// ErrOwnerSignature is returned if an owner signature could not be verified
	ErrOwnerSignature = registerTranslateError("issuer: owner signature verification failed", true)
	// ErrWrongIssuer is returned if a token is presented to the wrong issuer
	ErrWrongIssuer = registerTranslateError("issuer: wrong issuer", true)
	// ErrExpire is returned if a token has already expired
	ErrExpire = registerTranslateError("issuer: token expired", true)
	// ErrBadUsage is returned if a key is presented with the wrong usage setting
	ErrBadUsage = registerTranslateError("issuer: bad usage", true)
	// ErrBadIssuer is returned if a key is presented with the wrong issuer
	ErrBadIssuer = registerTranslateError("issuer: bad issuer", true)
	// ErrBadSignature is returned if a signature could not be verified
	ErrBadSignature = registerTranslateError("issuer: bad signature in token", true)
	// ErrParameterMixed is returned if the parameter set contains mixed keys
	ErrParameterMixed = registerTranslateError("issuer: parameters were mixed", true)
)
