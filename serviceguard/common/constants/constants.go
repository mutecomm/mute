// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package constants defines common serviceguard constants.
package constants

var (
	// KeyLookupPath is the URI path to the key lookup service
	KeyLookupPath = "/keylookup/"
	// KeyLookupInternalPath is the URI path to the key lookup service internal methods
	KeyLookupInternalPath = "/keylookup/int"
	// IssuerPath is the URI path to the issuer
	IssuerPath = "/rpc/"
	// IssuerInternalHost is appended to the host part for internal issuer calls
	IssuerInternalHost = "int"
	// IssuerInternalPathAddition is appended to the path for internal issuer calls
	IssuerInternalPathAddition = "int/"
	// IssuerInternalPath is the URI path to the issuer internal methods
	IssuerInternalPath = "/rpc/" + IssuerInternalPathAddition
	// WalletServerPath is the URI path to the wallet server
	WalletServerPath = "/wallet/"
	// WalletServerURL is the URL of the wallet service
	WalletServerURL = "https://walletserver.serviceguard.chavpn.net" + WalletServerPath
	// KeyLookupURL is the URL of the key lookup service
	KeyLookupURL = "https://keylookup.serviceguard.chavpn.net" + KeyLookupPath
	// KeyPostURL is the URL to post keys to for key lookup registration
	KeyPostURL = "https://keylookup.serviceguard.chavpn.net" + KeyLookupInternalPath
	// IssuerURL is the URL template for issuers. Notice the leading dot and trailing slash
	IssuerURL = "https://.serviceguard.chavpn.net" + IssuerPath
	// AuthTokenRetry defines how often an authToken should be retried by the client on non-final errors
	AuthTokenRetry = 3
	// ClientMaxLockAge defines how long a token should be locked at max in the tokenstore
	ClientMaxLockAge = int64(3600)
	// ClientExpireEdge defines how long before the expire-date a token should be reissued
	ClientExpireEdge = int64(604800)
)
