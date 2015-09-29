// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util/bzero"
)

// mutecryptAddContact makes the following mutecrypt calls for the given id
// and domain:
//   mutecrypt hashchain sync --domain
//   mutecrypt hashchain validate --domain
//   mutecrypt hashchain search --id
//
//TODO:
//  - kill mutecrypt process in case of failure?
//  - make more efficient
func mutecryptAddContact(
	c *cli.Context,
	passphrase []byte,
	id, domain, host string,
	client *client.Client,
) error {
	log.Infof("mutecryptAddContact(): id=%s, domain=%s", id, domain)
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
	}
	if host != "" {
		args = append(args,
			"--keyhost", host,
			"--keyport", ":8080") // TODO: remove keyport hack!
	}
	cmd := exec.Command("mutecrypt", args...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(stderr)

	passphraseReader, passphraseWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, passphraseReader)

	commandReader, commandWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, commandReader)

	// sync hash chain
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"hashchain", "sync", "--domain", domain + "\n",
	}, " "))
	if err != nil {
		return err
	}

	// start process
	if err := cmd.Start(); err != nil {
		return err
	}

	// write passphrase
	plen := len(passphrase)
	buf := make([]byte, plen+1)
	defer bzero.Bytes(buf)
	copy(buf, passphrase)
	copy(buf[plen:], []byte("\n"))
	if _, err := passphraseWriter.Write(buf); err != nil {
		return err
	}
	passphraseWriter.Close()

	// check for errors on stderr
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// validate hash chain
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"hashchain", "validate", "--domain", domain + "\n",
	}, " "))
	if err != nil {
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// make sure we have the key server key
	// TODO: is there a better way to do it?
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"hashchain", "search", "--id", "keyserver@" + domain + "\n",
	}, " "))
	if err != nil {
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// search hash chain
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"hashchain", "search", "--id", id + "\n",
	}, " "))
	if err != nil {
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// fetch KeyInit message for contact
	// TODO: this is not always necessary. Move somewhere else?
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"keyinit", "fetch", "--id", id + "\n",
	}, " "))
	if err != nil {
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// quit mutecrypt
	if _, err := io.WriteString(commandWriter, "quit\n"); err != nil {
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "QUITTING" {
			return errors.New(line)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func add(
	msgDB *msgdb.MsgDB,
	id, contact, fullName string,
	contactType msgdb.ContactType,
) error {
	contactMapped, err := identity.Map(contact)
	if err != nil {
		return err
	}

	// get contact first
	unmappedID, prevFullName, _, err := msgDB.GetContact(id, contactMapped)
	if err != nil {
		return err
	}
	if unmappedID != "" && fullName == "" {
		fullName = prevFullName
	}

	// add contact
	err = msgDB.AddContact(id, contactMapped, contact, fullName, contactType)
	if err != nil {
		return err
	}
	return nil
}

func get(outfp *os.File, msgDB *msgdb.MsgDB, id string, blocked bool) error {
	// get list of mapped contacts
	contacts, err := msgDB.GetContacts(id, blocked)
	if err != nil {
		return nil
	}

	// print list
	for _, contact := range contacts {
		fmt.Fprintln(outfp, contact)
	}

	return nil
}

func (ce *CtrlEngine) contactAdd(
	id, contact, fullName, host string,
	contactType msgdb.ContactType,
	c *cli.Context,
) error {
	idMapped, domain, err := identity.MapPlus(id)
	if err != nil {
		return err
	}
	contactMapped, domain, err := identity.MapPlus(contact)
	if err != nil {
		return err
	}
	err = mutecryptAddContact(c, ce.passphrase, contactMapped, domain, host, ce.client)
	if err != nil {
		return err
	}
	return add(ce.msgDB, idMapped, contactMapped, fullName, contactType)
}

func (ce *CtrlEngine) contactEdit(id, contact, fullName string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	contactMapped, err := identity.Map(contact)
	if err != nil {
		return err
	}
	unmappedID, _, contactType, err := ce.msgDB.GetContact(idMapped, contactMapped)
	if err != nil {
		return err
	}
	if unmappedID == "" {
		return log.Errorf("ctrlengine: contact %s unknown", contact)
	}
	err = ce.msgDB.AddContact(idMapped, contactMapped, contact, fullName,
		contactType)
	if err != nil {
		return err
	}
	return nil
}

func (ce *CtrlEngine) contactRemove(id, contact string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	contactMapped, err := identity.Map(contact)
	if err != nil {
		return err
	}
	// remove contact
	if err := ce.msgDB.RemoveContact(idMapped, contactMapped); err != nil {
		return err
	}
	return nil
}

func (ce *CtrlEngine) contactBlock(id, contact string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	contactMapped, err := identity.Map(contact)
	if err != nil {
		return err
	}

	// TODO: call mutecryptAddContact() like in addContact() ?
	return add(ce.msgDB, idMapped, contactMapped, "", msgdb.BlackList)
}

func (ce *CtrlEngine) contactUnblock(id, contact string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	contactMapped, err := identity.Map(contact)
	if err != nil {
		return err
	}

	// get contact
	unmappedID, fullName, contactType, err := ce.msgDB.GetContact(idMapped,
		contactMapped)
	if err != nil {
		return err
	}
	if contactType != msgdb.BlackList {
		return log.Errorf("ctrlengine: %s is not blocked", contact)
	}

	// unblock contact (-> white list)
	err = ce.msgDB.AddContact(idMapped, contactMapped, unmappedID, fullName,
		msgdb.WhiteList)
	if err != nil {
		return err
	}
	return nil
}

func (ce *CtrlEngine) contactList(outfp *os.File, id string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	return get(outfp, ce.msgDB, idMapped, false)
}

func (ce *CtrlEngine) contactBlacklist(outfp *os.File, id string) error {
	idMapped, err := identity.Map(id)
	if err != nil {
		return err
	}
	return get(outfp, ce.msgDB, idMapped, true)
}
