// Copyright (c) 2016 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mail implements email input messages in Mute.
package mail

import (
	"io"
	"io/ioutil"
	"net/mail"

	"github.com/mutecomm/mute/log"
)

// Parse parses a MIME encoded email for sending with Mute. It returns the
// intended recipient (parsed from mandatory the 'To' field) and the actual
// message (combined from the optional 'Subject field' plus the message body).
// It cannot handle attachments and/or multi-part messages.
func Parse(r io.Reader) (
	recipient string,
	message string,
	err error,
) {
	// read message
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return "", "", log.Error(err)
	}
	// parse 'To'
	recipient = msg.Header.Get("To")
	if recipient == "" {
		return "", "", log.Error("mail: 'To' not defined")
	}
	// parse 'Subject'
	subject := msg.Header.Get("Subject")
	// read body
	body, err := ioutil.ReadAll(msg.Body)
	if err != nil {
		return "", "", log.Error(err)
	}
	message = subject + "\n" + string(body)
	return
}
