// Package msgid contains helper functions for message ID generation and
// parsing.
package msgid

import (
	"encoding/hex"
	"io"
	"strings"
	"time"

	"github.com/mutecomm/mute/uid/identity"
)

// Generate generates a new messageID in the form
// "sender-year-month-hex(8byte-random)".
func Generate(sender string, rand io.Reader) (string, error) {
	if err := identity.IsMapped(sender); err != nil {
		return "", err
	}
	random := make([]byte, 8)
	if _, err := io.ReadFull(rand, random); err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("2006-01") // year-month
	return sender + "-" + ts + "-" + hex.EncodeToString(random), nil
}

// Parse parses the sender from the given messageID.
func Parse(messageID string) string {
	parts := strings.SplitN(messageID, "-", 2)
	if len(parts) != 2 {
		return "" // could not parse
	}
	return parts[0] // return sender
}
