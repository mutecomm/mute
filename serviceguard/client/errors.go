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
	ErrRetry = errors.New("client: Retry")
	// ErrOffline is returned if the client is offline
	ErrOffline = errors.New("client: Offline")
	// ErrFinal is returned on final errors that cannot continue
	ErrFinal = errors.New("client: Final serviceguard error")
	// ErrFatal is returned on fatal errors produced by the client implementation itself
	ErrFatal = errors.New("client: Fatal client error")
	// ErrNeedReissue is returned if a non-renewable token was issued by the walletserver but not owner was specified
	ErrNeedReissue = errors.New("client: Token needs reissue to owner")
	// ErrNotMine is returned if a token is not under our control
	ErrNotMine = errors.New("client: Not my token")
	// ErrLocked is returned if a token has been locked
	ErrLocked = errors.New("client: Token in use")
	// ErrExpireToken is returned if a token has expired
	ErrExpireToken = errors.New("client: Token expired")
	// ErrSignatureToken is returned if the token has a bad signature
	ErrSignatureToken = errors.New("client: Bad signature")
	// ErrOwnerToken is returned if a token has an unexpected owner
	ErrOwnerToken = errors.New("client: Unexpected owner")
	// ErrUsageToken is returned if a token has an unexpected usage
	ErrUsageToken = errors.New("client: Unexpected usage")
	// ErrTokenKnown is returned if a received token is already known
	ErrTokenKnown = errors.New("client: Token is already known")
	// ErrNoToken is returned if no token could be fetched from wallet storage
	ErrNoToken = errors.New("client: No token in wallet")
)

var (
	// Errors from wallet server:

	// ErrWalletServer is returned if the server experienced a problem that cannot be exposed to the client
	ErrWalletServer = registerTranslateError("walletserver: Server error", false)
	// ErrNoUser is returned if the user could not be found
	ErrNoUser = registerTranslateError("walletserver: No such user", true)
	// ErrBadToken is returned if the user's authtoken could not be verified
	ErrBadToken = registerTranslateError("walletserver: Bad token", true)
	// ErrInsufficientFunds is returned if the user's funds are exhausted
	ErrInsufficientFunds = registerTranslateError("walletserver: Insufficient funds", true)

	//
	// Errors from keylookup server:

	// ErrKeyLookupServer is returned if there was an error in the lookup server
	ErrKeyLookupServer = registerTranslateError("keylookup: Server error", false)
	// ErrNotFound is returned if the key could not be found
	ErrNotFound = registerTranslateError("keylookup: Key not found", true)

	//
	// Errors from issuer server:

	// ErrUsageMismatch is returned if the usage of the parameter publickey and the token publickey do not match
	ErrUsageMismatch = registerTranslateError("issuer: Parameter and Token usage mismatch", true)
	// ErrParamsExpired is returned if the parameters given are not in line with any available private key
	ErrParamsExpired = registerTranslateError("issuer: Parameters have expired", true)
	// ErrBadCallType is returned if a wrong calltype is present in a packet
	ErrBadCallType = registerTranslateError("issuer: Wrong calltype", true)
	// ErrIssuerServer is returned on server error
	ErrIssuerServer = registerTranslateError("issuer: Server errror", false)
	// ErrTokenDoubleSpend is returned if the token has already been spent
	ErrTokenDoubleSpend = registerTranslateError("issuer: Token double spend", true)
	// ErrParamDoubleSpend is returned if a parameter has already been spent
	ErrParamDoubleSpend = registerTranslateError("issuer: Parameter double spend", true)
	// ErrBadPacket is returned if packet contents cannot be unmarshalled
	ErrBadPacket = registerTranslateError("issuer: Bad package", true)
	// ErrOwnerSignature is returned if an owner signature could not be verified
	ErrOwnerSignature = registerTranslateError("issuer: Owner signature verification failed", true)
	// ErrWrongIssuer is returned if a token is presented to the wrong issuer
	ErrWrongIssuer = registerTranslateError("issuer: Wrong issuer", true)
	// ErrExpire is returned if a token has already expired
	ErrExpire = registerTranslateError("issuer: Token expired", true)
	// ErrBadUsage is returned if a key is presented with the wrong usage setting
	ErrBadUsage = registerTranslateError("issuer: Bad usage", true)
	// ErrBadIssuer is returned if a key is presented with the wrong issuer
	ErrBadIssuer = registerTranslateError("issuer: Bad issuer", true)
	// ErrBadSignature is returned if a signature could not be verified
	ErrBadSignature = registerTranslateError("issuer: Bad signature in token", true)
	// ErrParameterMixed is returned if the parameter set contains mixed keys
	ErrParameterMixed = registerTranslateError("issuer: Parameters were mixed", true)
)
