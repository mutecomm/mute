// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
// "year-month-hex(16byte-random)-sender".
func Generate(sender string, rand io.Reader) (string, error) {
	if err := identity.IsMapped(sender); err != nil {
		return "", err
	}
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand, random); err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("2006-01") // year-month
	return ts + "-" + hex.EncodeToString(random) + "-" + sender, nil
}

// Parse parses the sender from the given messageID and returns it.
// Returns "" in case of error.
func Parse(messageID string) string {
	parts := strings.SplitN(messageID, "-", 4)
	if len(parts) != 4 {
		return "" // could not parse
	}
	return parts[3] // return sender
}
