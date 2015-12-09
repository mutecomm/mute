// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"errors"
)

// ErrNotPreHeader is raised when a message doesn't start with a pre-header.
var ErrNotPreHeader = errors.New("msg: message doesn't start with pre-header")

// ErrNotEncryptedHeader is raised when a message doesn't has an encrypted
// header after the pre-header.
var ErrNotEncryptedHeader = errors.New("msg: message doesn't have encrypted header")

// ErrNotCryptoSetup is raised when a message doesn't has a crypto setup
// header after the encrypted header.
var ErrNotCryptoSetup = errors.New("msg: message doesn't have crypto setup header")

// ErrWrongCryptoSetup is raised when a crypto setup header has the wrong length.
var ErrWrongCryptoSetup = errors.New("msg: crypto setup header has the wrong length")

// ErrNotEncryptedPacket is raised when an encrypted packet was expected.
var ErrNotEncryptedPacket = errors.New("msg: expected encrypted packet")

// ErrNotPaddingPacket is raised when a padding packet was expected.
var ErrNotPaddingPacket = errors.New("msg: expected padding packet")

// ErrNotSignaturePacket is raised when a signature packet was expected.
var ErrNotSignaturePacket = errors.New("msg: expected signature packet")

// ErrWrongSignatureLength is raised when a signature has the wrong length.
var ErrWrongSignatureLength = errors.New("msg: wrong signature length")

// ErrInvalidSignature is raised when a signature verification failed.
var ErrInvalidSignature = errors.New("msg: signature invalid")

// ErrNotHMACPacket is raised when an HMAC packet was expected.
var ErrNotHMACPacket = errors.New("msg: expected HMAC packet")

// ErrHMACsDiffer is raised when the HMACs differ.
var ErrHMACsDiffer = errors.New("msg: HMACs differ")

// ErrWrongCount is raised when an outer header count is wrong.
var ErrWrongCount = errors.New("msg: wrong outer header count")

// ErrNotData is raised when an inner data header was expected.
var ErrNotData = errors.New("msg: expected inner data header")

// ErrMessageKeyUsed is raised when a message key has already been used.
var ErrMessageKeyUsed = errors.New("msg: message key has already been used")
