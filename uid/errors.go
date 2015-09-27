// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uid

import (
	"errors"
)

// ErrIncrement is raised when the MSGCOUNTER of an updated UID message was
// not incremented by one.
var ErrIncrement = errors.New("uid: message counter not incremented by one")

// ErrInvalidSelfSig is raised when the self-signature of an UID message is
// invalid.
var ErrInvalidSelfSig = errors.New("uid: self-signature invalid")

// ErrInvalidUserSig is raised when the self-signature of an UID message is
// invalid.
var ErrInvalidUserSig = errors.New("uid: user-signature invalid")

// ErrInvalidNonceSig is raised when the nonce signature created by a UID
// message is invalid.
var ErrInvalidNonceSig = errors.New("uid: nonce signature invalid")

// ErrMsgMismatch is raised when the UIDMessage in a UIDMessageReply doesn't
// match the original UIDMessage.
var ErrMsgMismatch = errors.New("uid: UIDMessageReply from key server doesn't match original UIDMessage")

// ErrInvalidSrvSig is raised when the server-signature of an UID message
// reply is invalid.
var ErrInvalidSrvSig = errors.New("uid: server-signature invalid (keyserver keys up-to-date?)")

// ErrInvalidTimes is raised when NOTAFTER and NOTBEFORE are invalid.
var ErrInvalidTimes = errors.New("uid: key init NOTBEFORE must be smaller than NOTAFTER")

// ErrExpired is raised when NOTAFTER has expired.
var ErrExpired = errors.New("uid: NOTAFTER has expired")

// ErrFuture is raised when NOTAFTER is too far in the future.
var ErrFuture = errors.New("uid: NOTAFTER is too far in the future")

// ErrRepoURI is raised when a KeyInit message has an invalid repo URI.
var ErrRepoURI = errors.New("uid: KeyInit has invalid repoURI")

// ErrWrongSigKeyHash is raised when the SIGKEYHASH of a KeyInit message
// does not match.
var ErrWrongSigKeyHash = errors.New("uid: KeyInit SIGKEYHASH does not match")

// ErrInvalidKeyInitSig is raised when the KeyInit signature is invalid.
var ErrInvalidKeyInitSig = errors.New("uid: KeyInit signature is invalid")

// ErrSessionAnchor is raised when the SESSIONANCHORHASH does not match the
// decrypted SESSIONANCHOR.
var ErrSessionAnchor = errors.New("uid: SESSIONANCHORHASH does not match decrypted SESSIONANCHOR")

// ErrKeyEntryNotFound is raised when a KeyEntry for a given function is
// not found.
var ErrKeyEntryNotFound = errors.New("uid: KeyEntry not found")
