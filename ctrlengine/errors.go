package ctrlengine

import (
	"errors"
)

// ErrPassphrasesDiffer is raised when the supplied passphrases during a DB
// creation or rekey operation differ.
var ErrPassphrasesDiffer = errors.New("ctrlengine: passphrases differ")
