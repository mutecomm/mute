// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"

	"github.com/mutecomm/mute/mix/mixcrypt"
	"github.com/mutecomm/mute/mix/nymaddr"
	"github.com/mutecomm/mute/mix/smtpclient"
	"github.com/mutecomm/mute/util/jsonclient"
)

// MaxMessageSize is the maximum size a message may have.
var MaxMessageSize = 266240

var (
	// ErrMaxSize is returned if a message is too long.
	ErrMaxSize = errors.New("mixclient: Message too long")
	// ErrNoHost is returned if no host could be selected.
	ErrNoHost = errors.New("mixclient: No RPC host found")
	// ErrNIL is returned when operating on nil value because of coding errors.
	ErrNIL = errors.New("mixclient: NIL value")
	// ErrAlreadySent is returned if trying to resend a message. Coding error!
	ErrAlreadySent = errors.New("mixclient: Already sent")
	// ErrProto is returned if there was a protocol error in RPC.
	ErrProto = errors.New("mixclient: Bad RPC protocol")
	// ErrNoMatch is returned if no account was found.
	ErrNoMatch = errors.New("mixclient: No match")
)

// DefaultClientFactory is the default factory for new clients.
var DefaultClientFactory = jsonclient.New

// DefaultAccountServer is the URL of the account server round-robin.
var DefaultAccountServer = "rr.accounts.mute.one"

// DefaultSender is the sender address for client messages.
var DefaultSender = "client@mute.berlin"

// DefaultTimeOut is the timeout for RPC calls.
var DefaultTimeOut = 30

// RPCPort is the default port for RPC calls.
var RPCPort = "2080"

func init() {
	registerError(ErrNIL)
	registerError(ErrAlreadySent)
	registerError(ErrMaxSize)

	registerError(smtpclient.ErrNoHost)
	registerError(smtpclient.ErrNoTLS)
	registerError(smtpclient.ErrNoAuth)
	registerError(smtpclient.ErrFinal)
	registerError(smtpclient.ErrRetry)

	registerError(mixcrypt.ErrNoKeys)
	registerError(mixcrypt.ErrTooShort)
	registerError(mixcrypt.ErrSize)
	registerError(mixcrypt.ErrBadSystem)

	registerError(nymaddr.ErrNoMix)
	registerError(nymaddr.ErrNoKey)
	registerError(nymaddr.ErrExpired)
	registerError(nymaddr.ErrHMAC)
	registerError(nymaddr.ErrBadKey)
}
