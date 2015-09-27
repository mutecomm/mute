// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgdb

import (
	"errors"
)

// ErrNilMessageID is returned if the messageID argument is nil.
var ErrNilMessageID = errors.New("msgdb: messageID nil")
