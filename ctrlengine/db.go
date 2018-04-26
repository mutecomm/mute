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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agl/ed25519"
	"github.com/frankbraun/codechain/util/bzero"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msgdb"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
)

func createKeyDB(
	c *cli.Context,
	w io.Writer,
	outputFD uintptr,
	passphrase []byte,
) error {
	args := []string{
		"--output-fd", strconv.Itoa(int(outputFD)),
		"--passphrase-fd", "stdin",
		"--homedir", c.GlobalString("homedir"),
		"--loglevel", c.GlobalString("loglevel"),
		"--logdir", c.GlobalString("logdir"),
	}
	if c.GlobalBool("logconsole") {
		args = append(args, "--logconsole")
	}
	args = append(args,
		"db", "create",
		"--iterations", strconv.Itoa(c.Int("iterations")),
	)
	cmd := exec.Command("mutecrypt", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var errbuf bytes.Buffer
	cmd.Stdout = w
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
	}
	return nil
}

// create a new MsgDB and KeyDB.
func (ce *CtrlEngine) dbCreate(
	w, statusfp io.Writer,
	homedir string,
	c *cli.Context,
) error {
	msgdbname := filepath.Join(c.GlobalString("homedir"), "msgs")
	// read passphrase
	fmt.Fprintf(statusfp, "read passphrase from fd %d (not echoed)\n",
		ce.fileTable.PassphraseFD)
	log.Infof("read passphrase from fd %d (not echoed)",
		ce.fileTable.PassphraseFD)
	var (
		scanner     *bufio.Scanner
		passphrase  []byte
		passphrase2 []byte
		err         error
	)
	defer bzero.Bytes(passphrase)
	defer bzero.Bytes(passphrase2)
	isTerminal := terminal.IsTerminal(int(ce.fileTable.PassphraseFD))
	if isTerminal {
		passphrase, err = terminal.ReadPassword(int(ce.fileTable.PassphraseFD))
		if err != nil {
			return log.Error(err)
		}
	} else {
		scanner = bufio.NewScanner(ce.fileTable.PassphraseFP)
		if scanner.Scan() {
			passphrase = scanner.Bytes()
		} else if err := scanner.Err(); err != nil {
			return log.Error(err)
		}
	}
	log.Info("done")
	// read passphrase again
	fmt.Fprintf(statusfp, "read passphrase from fd %d again (not echoed)\n",
		ce.fileTable.PassphraseFD)
	log.Infof("read passphrase from fd %d again (not echoed)",
		ce.fileTable.PassphraseFD)
	if isTerminal {
		passphrase2, err = terminal.ReadPassword(int(ce.fileTable.PassphraseFD))
		if err != nil {
			return log.Error(err)
		}
	} else {
		if scanner.Scan() {
			passphrase2 = scanner.Bytes()
		} else if err := scanner.Err(); err != nil {
			return log.Error(err)
		}
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
	if err := createKeyDB(c, w, ce.fileTable.OutputFD, passphrase); err != nil {
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
	return printWalletKey(w, walletKey)
}

func rekeyKeyDB(c *cli.Context, oldPassphrase, newPassphrase []byte) error {
	cmd := exec.Command("mutecrypt",
		"--passphrase-fd", "stdin",
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
	}
	return nil
}

// rekey MsgDB and KeyDB.
func (ce *CtrlEngine) dbRekey(statusfp io.Writer, c *cli.Context) error {
	msgdbname := filepath.Join(c.GlobalString("homedir"), "msgs")
	// read old passphrase
	fmt.Fprintf(statusfp, "read old passphrase from fd %d (not echoed)\n",
		ce.fileTable.PassphraseFD)
	log.Infof("read old passphrase from fd %d (not echoed)",
		ce.fileTable.PassphraseFD)
	var (
		scanner        *bufio.Scanner
		oldPassphrase  []byte
		newPassphrase  []byte
		newPassphrase2 []byte
		err            error
	)
	defer bzero.Bytes(oldPassphrase)
	defer bzero.Bytes(newPassphrase)
	defer bzero.Bytes(newPassphrase2)
	isTerminal := terminal.IsTerminal(int(ce.fileTable.PassphraseFD))
	if isTerminal {
		oldPassphrase, err = terminal.ReadPassword(int(ce.fileTable.PassphraseFD))
		if err != nil {
			return log.Error(err)
		}
	} else {
		scanner = bufio.NewScanner(ce.fileTable.PassphraseFP)
		if scanner.Scan() {
			oldPassphrase = scanner.Bytes()
		} else if err := scanner.Err(); err != nil {
			return log.Error(err)
		}
	}
	log.Info("done")
	// read new passphrase
	fmt.Fprintf(statusfp, "read new passphrase from fd %d (not echoed)\n",
		ce.fileTable.PassphraseFD)
	log.Infof("read new passphrase from fd %d (not echoed)",
		ce.fileTable.PassphraseFD)
	if isTerminal {
		newPassphrase, err = terminal.ReadPassword(int(ce.fileTable.PassphraseFD))
		if err != nil {
			return log.Error(err)
		}
	} else {
		if scanner.Scan() {
			newPassphrase = scanner.Bytes()
		} else if err := scanner.Err(); err != nil {
			return log.Error(err)
		}
	}
	log.Info("done")
	// read new passphrase again
	fmt.Fprintf(statusfp, "read new passphrase from fd %d again (not echoed)\n",
		ce.fileTable.PassphraseFD)
	log.Infof("read new passphrase from fd %d again (not echoed)",
		ce.fileTable.PassphraseFD)
	if isTerminal {
		newPassphrase2, err = terminal.ReadPassword(int(ce.fileTable.PassphraseFD))
		if err != nil {
			return log.Error(err)
		}
	} else {
		if scanner.Scan() {
			newPassphrase2 = scanner.Bytes()
		} else if err := scanner.Err(); err != nil {
			return log.Error(err)
		}
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
	return rekeyKeyDB(c, oldPassphrase, newPassphrase)
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
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
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(errbuf.String()))
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
