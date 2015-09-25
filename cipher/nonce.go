package cipher

import (
	"io"

	"github.com/mutecomm/mute/log"
)

// Nonce generates a random nonce.
//
// TODO: please review! Is RandReader OK or use PRNG from "math/rand"?
func Nonce(rand io.Reader) []byte {
	var b = make([]byte, 8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		panic(log.Critical(err))
	}
	return b
}
