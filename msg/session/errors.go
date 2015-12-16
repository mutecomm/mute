// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
)

// ErrMessageKeyUsed is raised when a message key has already been used.
var ErrMessageKeyUsed = errors.New("msg: message key has already been used")

// ErrNoKeyInit is raised when no KeyInit could be found.
var ErrNoKeyInit = errors.New("msg: no KeyInit for user found")
