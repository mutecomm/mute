// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/ctrlengine/mail"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/mix/mixcrypt"
	"github.com/mutecomm/mute/mix/nymaddr"
	"github.com/mutecomm/mute/msg"
	mimeMsg "github.com/mutecomm/mute/msg/mime"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/times"
	"github.com/mutecomm/mute/util/wallet"
	"github.com/peterh/liner"
	"github.com/urfave/cli"
)

func mutecryptEncrypt(
	c *cli.Context,
	from, to string,
	passphrase, msg []byte,
	sign bool,
	nymAddress string,
) (enc, nymaddress string, err error) {
	if err := identity.IsMapped(from); err != nil {
		return "", "", log.Error(err)
	}
	if err := identity.IsMapped(to); err != nil {
		return "", "", log.Error(err)
	}
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"encrypt",
		"--from", from,
		"--to", to,
		"--nymaddress", nymAddress,
	}
	if sign {
		args = append(args, "--sign")
	}
	cmd := exec.Command("mutecrypt", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", "", err
	}
	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	ppR, ppW, err := os.Pipe()
	if err != nil {
		return "", "", err
	}
	defer ppR.Close()
	ppW.Write(passphrase)
	ppW.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, ppR)
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	if _, err := stdin.Write(msg); err != nil {
		return "", "", err
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return "", "",
			fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
	}
	// parse nymaddress
	parts := strings.Split(strings.TrimSpace(errbuf.String()), "\t")
	if len(parts) != 2 || parts[0] != "NYMADDRESS:" {
		return "", "",
			fmt.Errorf("ctrlengine: mutecrypt status output not parsable: %s",
				strings.TrimSpace(errbuf.String()))
	}
	enc = outbuf.String()
	nymaddress = parts[1]
	return
}

func (ce *CtrlEngine) msgAdd(
	c *cli.Context,
	from, to, file string,
	mailInput, permanentSignature bool,
	attachments []string,
	minDelay, maxDelay int32,
	line *liner.State,
	r io.Reader,
) error {
	fromMapped, err := identity.Map(from)
	if err != nil {
		return err
	}
	prev, _, err := ce.msgDB.GetNym(fromMapped)
	if err != nil {
		return err
	}
	if prev == "" {
		return log.Errorf("user ID %s not found", from)
	}

	// TODO: handle attachments
	var msg []byte
	if file != "" {
		// read message from file
		msg, err = ioutil.ReadFile(file)
		if err != nil {
			return log.Error(err)
		}
	} else if line != nil {
		// read message from terminal
		fmt.Fprintln(ce.fileTable.StatusFP,
			"type message (end with Ctrl-D on empty line):")
		var inbuf bytes.Buffer
		for {
			ln, err := line.Prompt("")
			if err != nil {
				if err == io.EOF {
					break
				}
				return log.Error(err)
			}
			inbuf.WriteString(ln + "\n")
		}
		msg = inbuf.Bytes()
	} else {
		// read message from stdin
		msg, err = ioutil.ReadAll(r)
		if err != nil {
			return log.Error(err)
		}
	}

	if mailInput {
		recipient, message, err := mail.Parse(bytes.NewBuffer(msg))
		if err != nil {
			return err
		}
		to = recipient
		msg = []byte(message)
	}

	toMapped, err := identity.Map(to)
	if err != nil {
		return err
	}
	prev, _, contactType, err := ce.msgDB.GetContact(fromMapped, toMapped)
	if err != nil {
		return err
	}
	if prev == "" || contactType == msgdb.GrayList || contactType == msgdb.BlackList {
		return log.Errorf("contact %s not found (for user ID %s)", to, from)
	}

	// store message in message DB
	now := times.Now()
	err = ce.msgDB.AddMessage(fromMapped, toMapped, now, true, string(msg),
		permanentSignature, minDelay, maxDelay)
	if err != nil {
		return err
	}

	log.Info("message added")
	if line != nil {
		fmt.Fprintln(ce.fileTable.StatusFP, "message added")
	}

	return nil
}

func muteprotoCreate(
	c *cli.Context,
	msg string,
	minDelay, maxDelay int32,
	token, nymaddress string,
) (string, error) {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"create",
		"--mindelay", strconv.FormatInt(int64(minDelay), 10),
		"--maxdelay", strconv.FormatInt(int64(maxDelay), 10),
		"--token", token,
		"--nymaddress", nymaddress,
	}
	cmd := exec.Command("muteproto", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(stdin, msg); err != nil {
		return "", err
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
	}
	return outbuf.String(), nil
}

func muteprotoDeliver(
	c *cli.Context,
	envelope string,
) (resend bool, err error) {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"deliver",
	}
	cmd := exec.Command("muteproto", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return false, err
	}
	if _, err := io.WriteString(stdin, envelope); err != nil {
		return false, err
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return false,
			log.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
	}
	if len(errbuf.String()) > 0 {
		errstr := strings.TrimSpace(errbuf.String())
		if !strings.HasPrefix(errstr, "RESEND:\t") {
			return false,
				log.Errorf("ctrlengine: muteproto status output not parsable: %s", errstr)
		}
		log.Warn(errstr)
		resend = true
	}
	return
}

func (ce *CtrlEngine) procOutQueue(
	c *cli.Context,
	nym string,
	failDelivery bool,
) error {
	log.Debug("procOutQueue()")
	for {
		oqIdx, msg, nymaddress, minDelay, maxDelay, envelope, err :=
			ce.msgDB.GetOutQueue(nym)
		if err != nil {
			return err
		}
		if msg == "" {
			log.Debug("break")
			break // no more messages in outqueue
		}
		if !envelope {
			log.Debug("envelope")
			// parse nymaddress
			na, err := base64.Decode(nymaddress)
			if err != nil {
				return log.Error(na)
			}
			addr, err := nymaddr.ParseAddress(na)
			if err != nil {
				return err
			}
			// get token from wallet
			var pubkey [32]byte
			copy(pubkey[:], addr.TokenPubKey)
			token, err := wallet.GetToken(ce.client, "Message", &pubkey)
			if err != nil {
				return err
			}
			// `muteproto create`
			env, err := muteprotoCreate(c, msg, minDelay, maxDelay,
				base64.Encode(token.Token), nymaddress)
			if err != nil {
				return log.Error(err)
			}
			// update outqueue
			if err := ce.msgDB.SetOutQueue(oqIdx, env); err != nil {
				ce.client.UnlockToken(token.Hash)
				return err
			}
			ce.client.DelToken(token.Hash)
			msg = env
		}
		// `muteproto deliver`
		if failDelivery {
			return log.Error(ErrDeliveryFailed)
		}
		sendTime := times.Now() + int64(minDelay) // earliest
		resend, err := muteprotoDeliver(c, msg)
		if err != nil {
			// If the message delivery failed because the token expired in the
			// meantime we retract the message from the outqueue (setting it
			// back to 'ToSend') and start the delivery process for this
			// message all over again.
			// Matching the error message string is not optimal, but the best
			// available solution since the error results from calling another
			// binary (muteproto).
			if strings.HasSuffix(err.Error(), client.ErrFinal.Error()) {
				log.Debug("retract")
				if err := ce.msgDB.RetractOutQueue(oqIdx); err != nil {
					return err
				}
				continue
			}
			return log.Error(err)
		}
		if resend {
			// set resend status
			log.Debug("resend")
			if err := ce.msgDB.SetResendOutQueue(oqIdx); err != nil {
				return err
			}
		} else {
			// remove from outqueue
			log.Debug("remove")
			if err := ce.msgDB.RemoveOutQueue(oqIdx, sendTime); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ce *CtrlEngine) getNyms(id string, all bool) ([]string, error) {
	var nyms []string
	if all {
		ids, err := ce.msgDB.GetNyms(true)
		if err != nil {
			return nil, err
		}
		nyms = append(nyms, ids...)
	} else {
		idMapped, err := identity.Map(id)
		if err != nil {
			return nil, err
		}
		prev, _, err := ce.msgDB.GetNym(idMapped)
		if err != nil {
			return nil, err
		}
		if prev == "" {
			return nil, log.Errorf("user ID %s not found", id)
		}
		nyms = append(nyms, idMapped)
	}
	return nyms, nil
}

func (ce *CtrlEngine) msgSend(
	c *cli.Context,
	id string,
	all bool,
	failDelivery bool,
) error {
	nyms, err := ce.getNyms(id, all)
	if err != nil {
		return err
	}
	for _, nym := range nyms {
		// clear resend status for old messages in outqueue
		if err := ce.msgDB.ClearResendOutQueue(nym); err != nil {
			return err
		}

		// process old messages in outqueue
		if err := ce.procOutQueue(c, nym, failDelivery); err != nil {
			return err
		}

		/*
			ids, err := ce.msgDB.GetMsgIDs(nym)
			if err != nil {
				return err
			}
			for _, id := range ids {
				log.Debugf("id=%d, to=%s", id.MsgID, id.To)
			}
		*/

		// add all undelivered messages to outqueue
		var recvNymAddress string
		for {
			msgID, peer, msg, sign, minDelay, maxDelay, err :=
				ce.msgDB.GetUndeliveredMessage(nym)
			if err != nil {
				return err
			}
			if peer == "" {
				log.Debug("break")
				break // no more undelivered messages
			}

			// determine recipient nymaddress for encryption, if necessary
			if recvNymAddress == "" {
				// TODO! (implement more accounts? delay settings?)
				privkey, server, secret, minDelay, maxDelay, _, err :=
					ce.msgDB.GetAccount(nym, "")
				if err != nil {
					return err
				}
				_, domain, err := identity.Split(nym)
				if err != nil {
					return err
				}
				expire := times.ThirtyDaysLater() // TODO: make this settable
				singleUse := false                // TODO correct?
				var pubkey [ed25519.PublicKeySize]byte
				copy(pubkey[:], privkey[32:])
				_, recvNymAddress, err = util.NewNymAddress(domain, secret[:],
					expire, singleUse, minDelay, maxDelay, nym, &pubkey, server,
					def.CACert)
				if err != nil {
					return err
				}
			}

			// encrypt
			enc, nymaddress, err := mutecryptEncrypt(c, nym, peer,
				ce.passphrase, msg, sign, recvNymAddress)
			if err != nil {
				return log.Error(err)
			}
			// add to outqueue
			log.Debug("add")
			err = ce.msgDB.AddOutQueue(nym, msgID, enc, nymaddress,
				minDelay, maxDelay)
			if err != nil {
				return log.Error(err)
			}
		}

		// process new messages in outqueue
		if err := ce.procOutQueue(c, nym, failDelivery); err != nil {
			return err
		}
	}
	return nil
}

func muteprotoFetch(
	myID, contactID string,
	msgDB *msgdb.MsgDB,
	c *cli.Context,
	privkey, server string,
	lastMessageTime int64,
) (newMessageTime int64, err error) {
	log.Debug("muteprotoFetch()")
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"fetch",
		"--server", server,
		"--last-message-time", strconv.FormatInt(lastMessageTime, 10),
	}
	cmd := exec.Command("muteproto", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}
	ppR, ppW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer ppR.Close()
	ppW.Write([]byte(privkey))
	ppW.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, ppR)
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer cmdR.Close()
	defer cmdW.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, cmdR)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	var outbuf bytes.Buffer
	status := bufio.NewReader(stderr)
	input := make(chan []byte)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := stdout.Read(buf)
			if n > 0 {
				input <- buf[:n]
			}
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				return
			}
		}
	}()
	firstMessage := true
	cache, err := msgDB.GetMessageIDCache(myID, contactID)
	if err != nil {
		return 0, err
	}
	for {
		// read status output
		line, err := status.ReadString('\n')
		if err != nil {
			return 0, log.Error(err)
		}
		line = strings.TrimSpace(line)
		if line == "NONE" {
			log.Debug("read: NONE")
			break
		}
		if strings.HasSuffix(line, "accountdb: nothing found") {
			log.Info("account has no messages")
			return 0, nil
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || parts[0] != "MESSAGEID:" {
			return 0, log.Errorf("ctrlengine: MESSAGEID line expected from muteproto, got: %s", line)
		}
		messageID := parts[1]
		log.Debugf("read: MESSAGEID:\t%s", messageID)
		if cache[messageID] {
			// message known -> abort fetching messages and remove old IDs from cache
			log.Debug("write: QUIT")
			fmt.Fprintln(cmdW, "QUIT")
			err := msgDB.RemoveMessageIDCache(myID, contactID, messageID)
			if err != nil {
				return 0, log.Error(err)
			}
			break
		} else {
			// message unknown -> fetch it and add messageID to cache
			log.Debug("write: NEXT")
			fmt.Fprintln(cmdW, "NEXT")
			err := msgDB.AddMessageIDCache(myID, contactID, messageID)
			if err != nil {
				return 0, log.Error(err)
			}
		}
		// read message
		stop := make(chan uint64)
		done := make(chan bool)
		go func() {
			for {
				select {
				case buf := <-input:
					outbuf.Write(buf)
				case length := <-stop:
					for uint64(outbuf.Len()) < length {
						buf := <-input
						outbuf.Write(buf)
					}
					done <- true
					return
				}
			}
		}()
		// read LENGTH
		line, err = status.ReadString('\n')
		if err != nil {
			return 0, log.Error(err)
		}
		parts = strings.Split(strings.TrimRight(line, "\n"), "\t")
		if len(parts) != 2 || parts[0] != "LENGTH:" {
			return 0, log.Errorf("ctrlengine: LENGTH line expected from muteproto, got: %s", line)
		}
		length, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return 0, log.Error(err)
		}
		log.Debugf("read: LENGTH:\t%d", length)
		// read RECEIVETIME
		line, err = status.ReadString('\n')
		if err != nil {
			return 0, log.Error(err)
		}
		parts = strings.Split(strings.TrimRight(line, "\n"), "\t")
		if len(parts) != 2 || parts[0] != "RECEIVETIME:" {
			return 0, log.Errorf("ctrlengine: RECEIVETIME line expected from muteproto, got: %s", line)
		}
		receiveTime, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, log.Error(err)
		}
		log.Debugf("read: RECEIVETIME:\t%d", receiveTime)

		stop <- length
		<-done
		err = msgDB.AddInQueue(myID, contactID, receiveTime, outbuf.String())
		if err != nil {
			return 0, err
		}
		if firstMessage {
			newMessageTime = receiveTime
			firstMessage = false
		}
		outbuf.Reset()
	}
	if err := cmd.Wait(); err != nil {
		return 0, err
	}
	return
}

func mutecryptDecrypt(
	c *cli.Context,
	passphrase, enc []byte,
	statusFP io.Writer,
) (senderID, message string, err error) {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"decrypt",
	}
	cmd := exec.Command("mutecrypt", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", "", err
	}
	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	ppR, ppW, err := os.Pipe()
	if err != nil {
		return "", "", log.Error(err)
	}
	defer ppR.Close()
	ppW.Write(passphrase)
	ppW.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, ppR)
	if err := cmd.Start(); err != nil {
		return "", "", log.Error(err)
	}
	if _, err := stdin.Write(enc); err != nil {
		return "", "", log.Error(err)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		errstr := strings.TrimSpace(errbuf.String())
		if strings.HasSuffix(errstr, msg.ErrNoPreHeaderKey.Error()) {
			log.Warn("could not decrypt pre-header, message dropped")
			fmt.Fprintf(statusFP,
				"could not decrypt pre-header, message dropped\n")
			return "", "", nil
		}
		return "", "", log.Errorf("%s: %s", err, errstr)
	}
	// TODO: parse and process signature!
	scanner := bufio.NewScanner(&errbuf)
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || parts[0] != "SENDERIDENTITY:" {
			return "", "",
				log.Errorf("ctrlengine: mutecrypt status output not parsable: %s", line)
		}
		senderID = parts[1]
	} else {
		return "", "", log.Error("ctrlengine: expecting mutecrypt output")
	}
	if err := scanner.Err(); err != nil {
		return "", "", log.Error(err)
	}

	message = outbuf.String()
	return
}

func (ce *CtrlEngine) procInQueue(c *cli.Context, host string) error {
	log.Debug("procInQueue()")
	for {
		// get message from msgDB
		iqIdx, myID, contactID, msg, envelope, err := ce.msgDB.GetInQueue()
		if err != nil {
			return err
		}
		if myID == "" {
			log.Debug("no more messages in inqueue")
			break // no more messages in inqueue
		}
		if envelope {
			log.Debugf("decrypt envelope (iqIdx=%d)", iqIdx)
			// decrypt envelope
			message, err := base64.Decode(msg)
			if err != nil {
				return log.Error(err)
			}
			privkey, server, secret, _, _, _, err := ce.msgDB.GetAccount(myID, contactID)
			if err != nil {
				return err
			}
			receiveTemplate := nymaddr.AddressTemplate{
				Secret: secret[:],
			}
			var pubkey [32]byte
			copy(pubkey[:], privkey[32:])
			dec, nym, err := mixcrypt.ReceiveFromMix(receiveTemplate,
				util.MailboxAddress(&pubkey, server), message)
			if err != nil {
				return log.Error(err)
			}
			if !bytes.Equal(nym, cipher.SHA256([]byte(myID))) {
				// discard message
				log.Warnf("ctrlengine: hashed nym does not match %s -> discard message", myID)
				if err := ce.msgDB.DelInQueue(iqIdx); err != nil {
					return err
				}
			} else {
				log.Info("envelope successfully decrypted")
				err := ce.msgDB.SetInQueue(iqIdx, base64.Encode(dec))
				if err != nil {
					return err
				}
			}
		} else {
			log.Debugf("decrypt message (iqIdx=%d)", iqIdx)
			senderID, plainMsg, err := mutecryptDecrypt(c, ce.passphrase,
				[]byte(msg), ce.fileTable.StatusFP)
			if err != nil {
				return err
			}
			if senderID == "" {
				// message could not be decrypted, but we do not want to fail
				if err := ce.msgDB.DelInQueue(iqIdx); err != nil {
					return err
				}
				continue
			}
			// check if contact exists
			contact, _, contactType, err := ce.msgDB.GetContact(myID, senderID)
			if err != nil {
				return log.Error(err)
			}
			// TODO: we do not have to do request UID message from server
			// here, but we should use the one contained in the message and
			// compare it with hash chain entry (doesn't compromise anonymity)
			var drop bool
			if contact == "" {
				err := ce.contactAdd(myID, senderID, "", host, msgdb.GrayList, c)
				if err != nil {
					return log.Error(err)
				}
			} else if contactType == msgdb.BlackList {
				// messages from black listed contacts are dropped directly
				log.Debug("message from black listed contact dropped")
				drop = true
			}
			err = ce.msgDB.RemoveInQueue(iqIdx, plainMsg, senderID, drop)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ce *CtrlEngine) msgFetch(
	c *cli.Context,
	id string,
	all bool,
	host string,
) error {
	// process old messages in inqueue
	if err := ce.procInQueue(c, host); err != nil {
		return err
	}

	nyms, err := ce.getNyms(id, all)
	if err != nil {
		return err
	}

	// put new messages from server into in inqueue
	for _, nym := range nyms {
		contacts, err := ce.msgDB.GetAccounts(nym)
		if err != nil {
			return err
		}
		for _, contact := range contacts {
			privkey, server, _, _, _, lastMessageTime, err := ce.msgDB.GetAccount(nym, contact)
			if err != nil {
				return err
			}
			newMessageTime, err := muteprotoFetch(nym, contact, ce.msgDB, c,
				base64.Encode(privkey[:]), server, lastMessageTime)
			if err != nil {
				return log.Error(err)
			}
			if newMessageTime > 0 {
				err = ce.msgDB.SetAccountLastMsg(nym, contact, newMessageTime)
				if err != nil {
					return log.Error(err)
				}
			}
		}
	}

	// process new messages in inqueue
	return ce.procInQueue(c, host)
}

func (ce *CtrlEngine) msgList(w io.Writer, id string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	ids, err := ce.msgDB.GetMsgIDs(idMapped)
	if err != nil {
		return err
	}
	for _, id := range ids {
		var (
			direction rune
			status    rune
		)
		if id.Incoming {
			direction = '>'
			if id.Read {
				status = 'R'
			} else {
				status = 'N'
			}
		} else {
			direction = '<'
			if id.Sent {
				status = 'S'
			} else {
				status = 'P'
			}
		}
		fmt.Fprintf(w, "%c%c %d\t%s\t%s\t%s\t%s\n",
			direction,
			status,
			id.MsgID,
			time.Unix(id.Date, 0).Format(time.RFC3339),
			id.From,
			id.To,
			id.Subject)
	}
	return nil
}

func (ce *CtrlEngine) msgRead(w io.Writer, myID string, msgID int64) error {
	idMapped, err := identity.Map(myID)
	if err != nil {
		return err
	}
	from, to, msg, date, err := ce.msgDB.GetMessage(idMapped, msgID)
	if err != nil {
		return err
	}
	if err := ce.msgDB.ReadMessage(msgID); err != nil {
		return err
	}
	subject, message := mimeMsg.SplitMessage(msg)
	fmt.Fprintf(w, "Date: %s\r\n",
		time.Unix(date, 0).UTC().Format(time.RFC1123Z))
	fmt.Fprintf(w, "From: %s\r\n", from)
	fmt.Fprintf(w, "To: %s\r\n", to)
	if subject != "" {
		fmt.Fprintf(w, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	}
	fmt.Fprintf(w, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(w, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "%s", message)
	return nil
}

func (ce *CtrlEngine) msgDelete(myID string, msgID int64) error {
	idMapped, err := identity.Map(myID)
	if err != nil {
		return err
	}
	return ce.msgDB.DelMessage(idMapped, msgID)
}
