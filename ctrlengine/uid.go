// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/agl/ed25519"
	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/capabilities"
	"github.com/mutecomm/mute/log"
	mixclient "github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/bzero"
	"github.com/mutecomm/mute/util/times"
)

// TODO: extract method
func decodeED25519PubKeyBase64(p string) (*[ed25519.PublicKeySize]byte, error) {
	ret := new([ed25519.PublicKeySize]byte)
	pd, err := base64.Decode(p)
	if err != nil {
		return nil, err
	}
	copy(ret[:], pd)
	return ret, nil
}

func mutecryptNewUID(
	c *cli.Context,
	passphrase []byte,
	id, domain, host, mixaddress, nymaddress string,
	client *client.Client,
) error {
	log.Infof("mutecryptNewUID(): id=%s, domain=%s", id, domain)
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
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

	// generate UID
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"uid", "generate", "--id", id + "\n",
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

	// get capabilities
	args = []string{"caps", "show", "--domain", domain}
	if host := c.String("host"); host != "" {
		args = append(args, "--host", host)
	}
	args = append(args, "\n")
	_, err = io.WriteString(commandWriter, strings.Join(args, " "))
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
	var caps capabilities.Capabilities
	decoder := json.NewDecoder(stdout)
	if err := decoder.Decode(&caps); err != nil {
		return err
	}
	/*
		// pretty-print capabilities
		jsn, err := json.MarshalIndent(caps, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsn))
	*/

	owner, err := decodeED25519PubKeyBase64(caps.TKNPUBKEY)
	if err != nil {
		return err
	}
	// get token from wallet
	token, err := util.WalletGetToken(client, "UID", owner)
	if err != nil {
		return err
	}

	// try to register UID
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"uid", "register",
		"--id", id,
		"--token", base64.Encode(token.Token) + "\n",
	}, " "))
	if err != nil {
		// client.UnlockToken(token.Hash)
		return err
	}

	var cryptErr error
	for scanner.Scan() {
		line := scanner.Text()
		if line != "READY." {
			cryptErr = errors.New(line)
		} else {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		// client.UnlockToken(token.Hash)
		return err
	}

	// delete UID, if registration was not successful
	if cryptErr != nil {
		// client.UnlockToken(token.Hash)
		_, err = io.WriteString(commandWriter, strings.Join([]string{
			"uid", "delete",
			"--force",
			"--id", id + "\n",
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
	} else {
		// client.DelToken(token.Hash)
	}

	// add KeyInit messages
	token, err = util.WalletGetToken(client, "Message", owner)
	if err != nil {
		return err
	}
	_, err = io.WriteString(commandWriter, strings.Join([]string{
		"keyinit", "add",
		"--id", id,
		"--mixaddress", mixaddress,
		"--nymaddress", nymaddress,
		"--token", base64.Encode(token.Token) + "\n",
	}, " "))
	if err != nil {
		// client.UnlockToken(token.Hash)
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
		// client.UnlockToken(token.Hash)
		return err
	}
	// client.DelToken(token.Hash)

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
		//return fmt.Errorf("%s: %s", err, errbuf.String())
		return err
	}

	// propagate error
	if cryptErr != nil {
		return cryptErr
	}

	return nil
}

func (ce *CtrlEngine) uidNew(
	c *cli.Context,
	minDelay, maxDelay int32,
	host string,
) error {
	// make sure the ID is well-formed
	unmapped := c.String("id")
	id, domain, err := identity.MapPlus(unmapped)
	if err != nil {
		return err
	}

	// sync corresponding hashchain
	if id != "keyserver" {
		if err := ce.upkeepHashchain(c, domain, c.String("host")); err != nil {
			return err
		}
	}

	// TODO: check that ID has not been registered already (by the same or other user)

	// get token from wallet
	token, err := util.WalletGetToken(ce.client, def.AccdUsage, def.AccdOwner)
	if err != nil {
		return err
	}

	// register account for  UID
	_, privkey, err := ed25519.GenerateKey(cipher.RandReader)
	if err != nil {
		return log.Error(err)
	}
	server, err := mixclient.PayAccount(privkey, token.Token, "", def.CACert)
	if err != nil {
		ce.client.UnlockToken(token.Hash)
		return log.Error(err)
	}
	ce.client.DelToken(token.Hash)

	// generate secret for account
	var secret [64]byte
	if _, err := io.ReadFull(cipher.RandReader, secret[:]); err != nil {
		return err
	}

	// get mixaddress and nymaddress for KeyInit message
	expire := times.ThirtyDaysLater() // TODO: make this settable
	singleUse := false                // TODO correct?
	var pubkey [ed25519.PublicKeySize]byte
	copy(pubkey[:], privkey[32:])
	mixaddress, nymaddress, err := util.NewNymAddress(domain, secret[:], expire,
		singleUse, minDelay, maxDelay, id, &pubkey, server, def.CACert)
	if err != nil {
		return err
	}

	// generate UID
	err = mutecryptNewUID(c, ce.passphrase, id, domain, host, mixaddress,
		nymaddress, ce.client)
	if err != nil {
		return err
	}

	// save name mapping
	if err := ce.msgDB.AddNym(id, unmapped, c.String("full-name")); err != nil {
		return err
	}

	// register account for UID
	err = ce.msgDB.AddAccount(id, "", privkey, server, &secret)
	if err != nil {
		return err
	}

	// set active UID, if this was the first UID
	active, err := ce.msgDB.GetValue(msgdb.ActiveUID)
	if err != nil {
		return err
	}
	if active == "" {
		if err := ce.msgDB.AddValue(msgdb.ActiveUID, unmapped); err != nil {
			return err
		}
	}
	return nil
}

func (ce *CtrlEngine) uidEdit(unmappedID, fullName string) error {
	mappedID, err := identity.Map(unmappedID)
	if err != nil {
		return err
	}
	old, _, err := ce.msgDB.GetNym(mappedID)
	if err != nil {
		return err
	}
	if old == "" {
		return log.Errorf("user ID %s unknown", unmappedID)
	}
	if err := ce.msgDB.AddNym(mappedID, unmappedID, fullName); err != nil {
		return err
	}
	return nil
}

func (ce *CtrlEngine) uidActive(c *cli.Context) error {
	active, err := ce.msgDB.GetValue(msgdb.ActiveUID)
	if err != nil {
		return err
	}
	if active == "" {
		return errors.New("ctrlengine: no active nym in DB")
	}
	outputFD := c.GlobalInt("output-fd")
	log.Infof("write active nym to fd %d", outputFD)
	fp := os.NewFile(uintptr(outputFD), "output-fd")
	fmt.Fprintln(fp, active)
	return nil
}

func (ce *CtrlEngine) uidSwitch(unmappedID string) error {
	mappedID, err := identity.Map(unmappedID)
	if err != nil {
		return err
	}
	existing, _, err := ce.msgDB.GetNym(mappedID)
	if err != nil {
		return err
	}
	if existing == "" {
		return log.Errorf("user ID %s unknown", unmappedID)
	}
	if err := ce.msgDB.AddValue(msgdb.ActiveUID, mappedID); err != nil {
		return err
	}
	return nil
}

func mutecryptDeleteUID(c *cli.Context, id string, passphrase []byte) error {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"uid", "delete",
		"--id", id,
		"--force",
	}
	cmd := exec.Command("mutecrypt", args...)
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	ppR, ppW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ppR.Close()
	ppW.Write(passphrase)
	ppW.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, ppR)
	if err := cmd.Run(); err != nil {
		return log.Error(err)
	}
	return nil
}

func (ce *CtrlEngine) uidDelete(
	c *cli.Context,
	unmappedID string,
	force bool,
	statfp io.Writer,
) error {
	mappedID, err := identity.Map(unmappedID)
	if err != nil {
		return err
	}

	// make sure user ID is in message DB
	prev, _, err := ce.msgDB.GetNym(mappedID)
	if err != nil {
		return err
	}
	if prev == "" {
		return log.Errorf("ctrlengine: user ID '%s' unknown", unmappedID)
	}

	// ask for manual confirmation
	if !force {
		fmt.Fprintf(statfp, "ctrlengine: delete user ID %s and all contacts and messages? ",
			unmappedID)
		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return log.Error(err)
		}
		if !strings.HasPrefix(strings.ToLower(response), "y") {
			return log.Error("ctrlengine: user ID deletion aborted")
		}
	}

	// get account information before deletion
	contacts, err := ce.msgDB.GetAccounts(mappedID)
	if err != nil {
		return err
	}
	var privkeys []*[ed25519.PrivateKeySize]byte
	var servers []string
	for _, contact := range contacts {
		privkey, server, _, _, err := ce.msgDB.GetAccount(mappedID, contact)
		if err != nil {
			return err
		}
		privkeys = append(privkeys, privkey)
		servers = append(servers, server)
	}

	// remove user ID from message DB
	if err := ce.msgDB.DeleteNym(mappedID); err != nil {
		return err
	}

	// remove user ID from key DB
	if err := mutecryptDeleteUID(c, mappedID, ce.passphrase); err != nil {
		return err
	}

	// delete corresponding accounts. It doesn't matter that much, if this
	// fails because the accounts will expiry eventually.
	for i, privkey := range privkeys {
		err := mixclient.DeleteAccount(privkey, servers[i], def.CACert)
		if err != nil {
			return log.Error(err)
		}
	}

	return nil
}

func (ce *CtrlEngine) uidList(outfp io.Writer) error {
	nyms, err := ce.msgDB.GetNyms(false)
	if err != nil {
		return err
	}

	for _, nym := range nyms {
		fmt.Fprintln(outfp, nym)
	}
	return nil
}
