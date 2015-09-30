// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package capabilities defines the capabilities of the Mute key server.
package capabilities

// The Capabilities of a Mute key server. See:
// https://github.com/mutecomm/mute/blob/master/doc/keyserver.md#api
type Capabilities struct {
	METHODS               []string // methods implemented from specification
	DOMAINS               []string // domains served
	KEYREPOSITORYURIS     []string // Key repository URIs
	KEYINITREPOSITORYURIS []string // KeyInit repository URIs
	KEYHASHCHAINURIS      []string // Key Hashchain URIs
	KEYHASHCHAINENTRY     string   // last Key Hashchain entry
	TKNPUBKEY             string   // public wallet key for key server payment tokens
	SIGPUBKEYS            []string // public signature key(s) of keyserver
}
