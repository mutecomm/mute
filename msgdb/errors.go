package msgdb

import (
	"errors"
)

// ErrNilMessageID is returned if the messageID argument is nil.
var ErrNilMessageID = errors.New("msgdb: messageID nil")
