// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"errors"
)

// ErrPassphrasesDiffer is raised when the supplied passphrases during a DB
// creation or rekey operation differ.
var ErrPassphrasesDiffer = errors.New("ctrlengine: passphrases differ")

// ErrUserIDOwned is raised during UID message creation, if a user ID is
// already owned by the same user
var ErrUserIDOwned = errors.New("user ID already owned")

// ErrUserIDTaken is raised during UID message creation, if a user ID is
// already taken by another user.
var ErrUserIDTaken = errors.New("user ID already taken")

// ErrDeliveryFailed is raised when the message delivery failed due to option
// --fail-delivery.
var ErrDeliveryFailed = errors.New("ctrlengine: delivery failed")
