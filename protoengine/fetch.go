// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protoengine

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/util"
)

func (pe *ProtoEngine) fetch(
	output io.Writer,
	status io.Writer,
	server string,
	lastMessageTime int64,
	command io.Reader,
) error {
	// read passphrase
	log.Infof("read passphrase from fd %d", pe.fileTable.PassphraseFD)
	pks, err := util.Readline(pe.fileTable.PassphraseFP)
	if err != nil {
		return err
	}
	log.Info("done")
	pk, err := base64.Decode(string(pks))
	if err != nil {
		return log.Error(err)
	}
	var privkey [ed25519.PrivateKeySize]byte
	copy(privkey[:], pk)
	messages, err := client.ListMessages(&privkey, lastMessageTime, server,
		def.CACert)
	if err != nil {
		// TODO: handle this better
		if err.Error() == "accountdb: Nothing found" {
			// no messages found
			log.Info("write: NONE")
			fmt.Fprintln(status, "NONE")
			return nil
		}
		return log.Error(err)
	}
	scanner := bufio.NewScanner(command)
	for _, message := range messages {
		msg, err := client.FetchMessage(&privkey, message.MessageID, server,
			def.CACert)
		if err != nil {
			return log.Error(err)
		}
		messageID := base64.Encode(message.MessageID)
		log.Debugf("write: MESSAGEID:\t%s", messageID)
		fmt.Fprintf(status, "MESSAGEID:\t%s\n", messageID)
		var command string
		if scanner.Scan() {
			command = scanner.Text()
		} else {
			return log.Error("protoengine: expecting command input")
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "reading standard input:", err)
		}
		if command == "NEXT" {
			log.Debug("read: NEXT")
			enc := base64.Encode(msg)
			if _, err := io.WriteString(output, enc); err != nil {
				return log.Error(err)
			}
			log.Debugf("write: LENGTH:\t%d", len(enc))
			fmt.Fprintf(status, "LENGTH:\t%d\n", len(enc))
			log.Debugf("write: RECEIVETIME:\t%d", message.ReceiveTime)
			fmt.Fprintf(status, "RECEIVETIME:\t%d\n", message.ReceiveTime)
		} else if command == "QUIT" {
			log.Debug("read: QUIT")
			return nil
		} else {
			return log.Errorf("protoengine: unknown command '%s'", command)
		}
	}
	// no more messages
	log.Info("write: NONE")
	fmt.Fprintln(status, "NONE")
	return nil
}
