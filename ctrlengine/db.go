// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"

	"github.com/agl/ed25519"
	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/util/bzero"
)

func createKeyDB(c *cli.Context, passphrase []byte) error {
	cmd := exec.Command("mutecrypt",
		"--passphrase-fd", "0",
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "create",
		"--iterations", strconv.Itoa(c.Int("iterations")))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return err
	}
	plen := len(passphrase)
	buf := make([]byte, plen+1+plen+1)
	defer bzero.Bytes(buf)
	copy(buf, passphrase)
	copy(buf[plen:], []byte("\n"))
	copy(buf[plen+1:], passphrase)
	copy(buf[plen+1+plen:], []byte("\n"))
	if _, err := stdin.Write(buf); err != nil {
		return err
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

// create a new MsgDB and KeyDB.
func (ce *CtrlEngine) dbCreate(
	w, statusfp io.Writer,
	homedir string,
	c *cli.Context,
) error {
	msgdbname := path.Join(c.GlobalString("homedir"), "msgs")
	// read passphrase
	passphraseFD := c.GlobalInt("passphrase-fd")
	fmt.Fprintf(statusfp, "read passphrase from fd %d\n", passphraseFD)
	log.Infof("read passphrase from fd %d", passphraseFD)
	fp := os.NewFile(uintptr(passphraseFD), "passphrase-fd")
	scanner := bufio.NewScanner(fp)
	var passphrase []byte
	defer bzero.Bytes(passphrase)
	if scanner.Scan() {
		passphrase = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return log.Error(err)
	}
	log.Info("done")
	// read passphrase again
	fmt.Fprintf(statusfp, "read passphrase from fd %d again\n", passphraseFD)
	log.Infof("read passphrase from fd %d again", passphraseFD)
	var passphrase2 []byte
	defer bzero.Bytes(passphrase2)
	if scanner.Scan() {
		passphrase2 = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return log.Error(err)
	}
	log.Info("done")
	// compare passphrases
	if !bytes.Equal(passphrase, passphrase2) {
		return log.Error(ErrPassphrasesDiffer)
	}
	// create msgDB
	log.Infof("create msgDB '%s'", msgdbname)
	if err := msgdb.Create(msgdbname, passphrase, c.Int("iterations")); err != nil {
		return err
	}
	// open msgDB
	msgDB, err := msgdb.Open(msgdbname, passphrase)
	if err != nil {
		return err
	}
	defer msgDB.Close()
	// configure to make sure mutecrypt has config file
	err = ce.upkeepFetchconf(msgDB, homedir, false, nil, statusfp)
	if err != nil {
		return err
	}
	// create keyDB
	log.Info("create keyDB")
	if err := createKeyDB(c, passphrase); err != nil {
		return err
	}
	// status
	fmt.Fprintf(statusfp, "database files created\n")
	log.Info("database files created")
	// determine private walletKey
	walletKey := c.String("walletkey")
	if walletKey == "" {
		// generate wallet key
		_, privateKey, err := ed25519.GenerateKey(cipher.RandReader)
		if err != nil {
			return err
		}
		walletKey = base64.Encode(privateKey[:])
	}
	// store wallet key
	if err := msgDB.AddValue(msgdb.WalletKey, walletKey); err != nil {
		return err
	}
	// print wallet key
	if err := printWalletKey(w, walletKey); err != nil {
		return err
	}
	return nil
}

func rekeyKeyDB(c *cli.Context, oldPassphrase, newPassphrase []byte) error {
	cmd := exec.Command("mutecrypt",
		"--passphrase-fd", "0",
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "rekey",
		"--iterations", strconv.Itoa(c.Int("iterations")))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return err
	}
	olen := len(oldPassphrase)
	nlen := len(newPassphrase)
	buf := make([]byte, olen+1+nlen+1+nlen+1)
	defer bzero.Bytes(buf)
	copy(buf, oldPassphrase)
	copy(buf[olen:], []byte("\n"))
	copy(buf[olen+1:], newPassphrase)
	copy(buf[olen+1+nlen:], []byte("\n"))
	copy(buf[olen+1+nlen+1:], newPassphrase)
	copy(buf[olen+1+nlen+1+nlen:], []byte("\n"))
	if _, err := stdin.Write(buf); err != nil {
		return err
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

// rekey MsgDB and KeyDB.
func (ce *CtrlEngine) dbRekey(statusfp io.Writer, c *cli.Context) error {
	msgdbname := path.Join(c.GlobalString("homedir"), "msgs")
	// read old passphrase
	passphraseFD := c.GlobalInt("passphrase-fd")
	fmt.Fprintf(statusfp, "read old passphrase from fd %d\n", passphraseFD)
	log.Infof("read old passphrase from fd %d", passphraseFD)
	fp := os.NewFile(uintptr(passphraseFD), "passphrase-fd")
	scanner := bufio.NewScanner(fp)
	var oldPassphrase []byte
	defer bzero.Bytes(oldPassphrase)
	if scanner.Scan() {
		oldPassphrase = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return log.Error(err)
	}
	log.Info("done")
	// read new passphrase
	fmt.Fprintf(statusfp, "read new passphrase from fd %d\n", passphraseFD)
	log.Infof("read new passphrase from fd %d", passphraseFD)
	var newPassphrase []byte
	defer bzero.Bytes(newPassphrase)
	if scanner.Scan() {
		newPassphrase = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return log.Error(err)
	}
	log.Info("done")
	// read new passphrase again
	fmt.Fprintf(statusfp, "read new passphrase from fd %d again\n", passphraseFD)
	log.Infof("read new passphrase from fd %d again", passphraseFD)
	var newPassphrase2 []byte
	defer bzero.Bytes(newPassphrase2)
	if scanner.Scan() {
		newPassphrase2 = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return log.Error(err)
	}
	log.Info("done")
	// compare new passphrases
	if !bytes.Equal(newPassphrase, newPassphrase2) {
		return log.Error(ErrPassphrasesDiffer)
	}
	// rekey msgDB
	log.Infof("rekey msgDB '%s'", msgdbname)
	if err := msgdb.Rekey(msgdbname, oldPassphrase, newPassphrase, c.Int("iterations")); err != nil {
		return err
	}
	// rekey keyDB
	log.Info("rekey keyDB")
	if err := rekeyKeyDB(c, oldPassphrase, newPassphrase); err != nil {
		return err
	}
	return nil
}

func mutecryptDBStatus(c *cli.Context, w io.Writer, passphrase []byte) error {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "status",
	}
	cmd := exec.Command("mutecrypt", args...)
	cmd.Stdout = w
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
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

func (ce *CtrlEngine) dbStatus(c *cli.Context, w io.Writer) error {
	autoVacuum, freelistCount, err := ce.msgDB.Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "msgdb:\n")
	fmt.Fprintf(w, "auto_vacuum=%s\n", autoVacuum)
	fmt.Fprintf(w, "freelist_count=%d\n", freelistCount)
	if err := mutecryptDBStatus(c, w, ce.passphrase); err != nil {
		return log.Error(err)
	}
	return nil
}

func mutecryptDBVacuum(
	c *cli.Context,
	passphrase []byte,
	autoVacuumMode string,
) error {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "vacuum",
	}
	if autoVacuumMode != "" {
		args = append(args, "--auto-vacuum", autoVacuumMode)
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
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

func (ce *CtrlEngine) dbVacuum(c *cli.Context, autoVacuumMode string) error {
	if err := ce.msgDB.Vacuum(autoVacuumMode); err != nil {
		return err
	}
	if err := mutecryptDBVacuum(c, ce.passphrase, autoVacuumMode); err != nil {
		return log.Error(err)
	}
	return nil
}

func mutecryptDBIncremental(
	c *cli.Context,
	passphrase []byte,
	pages int64,
) error {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "incremental",
	}
	if pages != 0 {
		args = append(args, "--pages", strconv.FormatInt(pages, 10))
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
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

func (ce *CtrlEngine) dbIncremental(c *cli.Context, pagesToRemove int64) error {
	if err := ce.msgDB.Incremental(pagesToRemove); err != nil {
		return err
	}
	err := mutecryptDBIncremental(c, ce.passphrase, pagesToRemove)
	if err != nil {
		return log.Error(err)
	}
	return nil
}

func mutecryptDBVersion(c *cli.Context, w io.Writer, passphrase []byte) error {
	args := []string{
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
		"db", "version",
	}
	cmd := exec.Command("mutecrypt", args...)
	cmd.Stdout = w
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
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", err, errbuf.String())
	}
	return nil
}

func (ce *CtrlEngine) dbVersion(c *cli.Context, w io.Writer) error {
	version, err := ce.msgDB.Version()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "msgdb:\n")
	fmt.Fprintf(w, "version=%s\n", version)
	if err := mutecryptDBVersion(c, w, ce.passphrase); err != nil {
		return log.Error(err)
	}
	return nil
}
