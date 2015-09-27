// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cryptengine implements the command engine for mutecrypt.
package cryptengine

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/cryptengine/cache"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/keydb"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/bzero"
	"github.com/mutecomm/mute/util/home"
)

const (
	nodb     = "no keyDB"
	locked   = "locked keyDB"
	unlocked = "unlocked keyDB"
)

var (
	defaultHomeDir = home.AppDataDir("mute", false)
	defaultLogDir  = path.Join(defaultHomeDir, "log")
	errExit        = errors.New("cryptengine: requests exit")
)

// CryptEngine abstracts a mutecrypt command engine.
type CryptEngine struct {
	prepared bool
	keydHost string
	keydPort string
	homedir  string
	outputfp *os.File

	keyDB *keydb.KeyDB
	cache *cache.Cache

	app *cli.App
	err error
}

func (ce *CryptEngine) prepare(c *cli.Context, openKeyDB bool) error {
	if !ce.prepared {
		ce.keydHost = c.GlobalString("keyhost")
		ce.keydPort = c.GlobalString("keyport")
		ce.homedir = c.GlobalString("homedir")
		ce.outputfp = os.NewFile(uintptr(c.GlobalInt("output-fd")), "output-fd")

		// create the necessary directories if they don't already exist
		err := util.CreateDirs(c.GlobalString("homedir"), c.GlobalString("logdir"))
		if err != nil {
			return err
		}

		// initialize logging framework
		err = log.Init(c.GlobalString("loglevel"), "crypt",
			c.GlobalString("logdir"), c.GlobalBool("logconsole"))
		if err != nil {
			return err
		}

		// configure
		if !c.GlobalBool("keyserver") {
			if err := def.InitMuteFromFile(ce.homedir); err != nil {
				return err
			}
		}

		ce.prepared = true
	}

	// open KeyDB, if necessary
	if openKeyDB {
		if ce.keyDB == nil && !c.GlobalBool("keyserver") {
			if err := ce.openKeyDB(c.GlobalInt("passphrase-fd")); err != nil {
				return err
			}
		}
	}

	return nil
}

// loop runs the crypt engine in a loop and reads commands from the file
// descriptor command-fd.
func (ce *CryptEngine) loop(c *cli.Context) {
	if len(c.Args()) > 0 {
		ce.err = fmt.Errorf("cryptengine: unknown command '%s', try 'help'",
			strings.Join(c.Args(), " "))
		return
	}

	log.Info("cryptengine: starting")

	// run command(s)
	cmdfd := c.Int("command-fd")
	log.Infof("read commands from fd %d", cmdfd)
	statusfp := os.NewFile(uintptr(c.Int("status-fd")), "status-fd")

	scanner := bufio.NewScanner(os.NewFile(uintptr(cmdfd), "command-fd"))

	for scanner.Scan() {
		args := []string{ce.app.Name}
		line := scanner.Text()
		if line == "" {
			log.Infof("read empty line")
			continue
		}
		log.Infof("read: %s", line)
		args = append(args, strings.Fields(line)...)
		if err := ce.app.Run(args); err != nil {
			// command execution failed -> issue status and continue
			log.Infof("command execution failed (app): %s", err)
			fmt.Fprintln(statusfp, err)
			continue
		}
		if ce.err != nil {
			if ce.err == errExit {
				// exit requested -> return
				log.Info("cryptengine: stopping (exit requested)")
				fmt.Fprintln(statusfp, "QUITTING")
				ce.err = nil
				return
			}
			// command execution failed -> issue status and continue
			log.Infof("command execution failed (cmd): %s", ce.err)
			fmt.Fprintln(statusfp, ce.err)
			ce.err = nil
		} else {
			log.Info("command successful")
		}
		fmt.Fprintln(statusfp, "READY.")
	}
	if err := scanner.Err(); err != nil {
		ce.err = log.Errorf("cryptengine: %s", err)
	}
	log.Info("cryptengine: stopping (error)")
	return
}

// New returns a new Mute crypt engine.
func New() *CryptEngine {
	var ce CryptEngine
	ce.app = cli.NewApp()
	ce.app.Usage = "tool to handle message encryption/decryption and key management"
	ce.app.Version = def.Version
	ce.app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "homedir",
			Value: defaultHomeDir,
			Usage: "set home directory",
		},
		cli.BoolFlag{
			Name:  "keyserver",
			Usage: "create key for key server",
		},
		cli.StringFlag{
			Name:  "keyhost",
			Usage: "alternative hostname for key server",
		},
		cli.StringFlag{
			Name:  "keyport",
			Value: def.Portmutekeyd,
			Usage: "key server port",
		},
		cli.IntFlag{
			Name:  "input-fd",
			Value: 0,
			Usage: "input file descriptor",
		},
		cli.IntFlag{
			Name:  "output-fd",
			Value: 1,
			Usage: "output file descriptor",
		},
		cli.IntFlag{
			Name:  "status-fd",
			Value: 2,
			Usage: "status file descriptor",
		},
		cli.IntFlag{
			Name:  "passphrase-fd",
			Value: 3,
			Usage: "passphrase file descriptor",
		},
		cli.IntFlag{
			Name:  "command-fd",
			Value: 4,
			Usage: "command file descriptor",
		},
		cli.StringFlag{
			Name:  "loglevel",
			Value: "info",
			Usage: "logging level {trace, debug, info, warn, error, critical}",
		},
		cli.StringFlag{
			Name:  "logdir",
			Value: defaultLogDir,
			Usage: "directory to log output",
		},
		cli.BoolFlag{
			Name:  "logconsole",
			Usage: "enable logging to console",
		},
	}
	ce.app.Before = func(c *cli.Context) error {
		return ce.prepare(c, false)
	}
	ce.app.Action = func(c *cli.Context) {
		ce.loop(c)
	}
	ce.app.Commands = []cli.Command{
		{
			Name:  "db",
			Usage: "commands for local key database",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "Create KeyDB",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "iterations",
							Value: def.KDFIterationsDB,
							Usage: "number of KDF iterations used for KeyDB creation",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						return ce.prepare(c, false)
					},
					Action: func(c *cli.Context) {
						ce.err = ce.create(c.GlobalString("homedir"), c.Int("iterations"),
							c.GlobalInt("passphrase-fd"))
					},
				},
				{
					Name:  "rekey",
					Usage: "Rekey KeyDB",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "iterations",
							Value: def.KDFIterationsDB,
							Usage: "number of KDF iterations used for KeyDB rekeying",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						return ce.prepare(c, false)
					},
					Action: func(c *cli.Context) {
						ce.err = ce.rekey(c.GlobalString("homedir"), c.Int("iterations"),
							c.GlobalInt("passphrase-fd"))
					},
				},
				{
					Name:  "status",
					Usage: "Show DB status",
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outputfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.dbStatus(outputfp)
					},
				},
				{
					Name:  "vacuum",
					Usage: "Do full DB rebuild (VACUUM)",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "auto-vacuum",
							Usage: "also change auto_vacuum mode (possible modes: NONE, FULL, INCREMENTAL)",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.dbVacuum(c.String("auto-vacuum"))
					},
				},
				{
					Name:  "incremental",
					Usage: "Remove free pages in auto_vacuum=INCREMENTAL mode",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "pages",
							Usage: "number of pages to remove (default: all)",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.dbIncremental(int64(c.Int("pages")))
					},
				},
			},
		},
		{
			Name:  "caps",
			Usage: "commands for key server capabilities",
			Subcommands: []cli.Command{
				{
					Name:  "get",
					Usage: "get key server capabilities",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "domain",
							Usage: "key server domain [:port]",
						},
						cli.StringFlag{
							Name:  "host",
							Usage: "alternative hostname",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("domain") {
							return log.Error("option --domain is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.getCapabilities(c.String("domain"), c.String("host"))
					},
				},
				{
					Name:  "show",
					Usage: "show key server capabilities",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "domain",
							Usage: "key server domain",
						},
						cli.StringFlag{
							Name:  "host",
							Usage: "alternative hostname",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("domain") {
							return log.Error("option --domain is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.showCapabilities(c.String("domain"), c.String("host"))
					},
				},
			},
		},
		{
			Name:  "uid",
			Usage: "commands for user IDs",
			Subcommands: []cli.Command{
				{
					Name:  "generate",
					Usage: "generate a user ID",
					Description: `
Generates a new user ID (UID) and stores the keys locally, but doesn't
register the UID message with the keyserver yet.
`,
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID to generate",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.generate(c.String("id"), c.GlobalBool("keyserver"),
							ce.outputfp)
					},
				},
				{
					Name:  "register",
					Usage: "register user ID",
					Description: `
Tries to register a pregenerated UID message with the corresponding keyserver.
`,
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID to register",
						},
						cli.StringFlag{
							Name:  "token",
							Usage: "payment token",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("token") {
							return log.Error("option --token is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.register(c.String("id"), c.String("token"))
					},
				},
				{
					Name:  "genupdate",
					Usage: "generate update for user ID",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID to update",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.genupdate(c.String("id"))
					},
				},
				{
					Name:  "update",
					Usage: "update user ID",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID to update",
						},
						cli.StringFlag{
							Name:  "token",
							Usage: "payment token",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("token") {
							return log.Error("option --token is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.update(c.String("id"), c.String("token"))
					},
				},
				{
					Name:  "delete",
					Usage: "delete user ID",
					Description: `
Delete a user ID (registered or unregistered).
`,
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID to delete",
						},
						cli.BoolFlag{
							Name:  "force",
							Usage: "force deletion (do not prompt)",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.deleteUID(c.String("id"), c.Bool("force"))
					},
				},
				{
					Name:  "list",
					Usage: "list own (mapped) user IDs",
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.listUIDs(outfp)
					},
				},
			},
		},
		{
			Name:  "keyinit",
			Usage: "commands for KeyInit messages",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "add new KeyInit message",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID",
						},
						cli.StringFlag{
							Name:  "mixaddress",
							Usage: "mix address for KeyInit message",
						},
						cli.StringFlag{
							Name:  "nymaddress",
							Usage: "nym address for KeyInit message",
						},
						cli.StringFlag{
							Name:  "token",
							Usage: "payment token",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("mixaddress") {
							return log.Error("option --mixaddress is mandatory")
						}
						if !c.IsSet("nymaddress") {
							return log.Error("option --nymaddress is mandatory")
						}
						if !c.IsSet("token") {
							return log.Error("option --token is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.addKeyInit(c.String("id"),
							c.String("mixaddress"), c.String("nymaddress"),
							c.String("token"))
					},
				},
				{
					Name:  "fetch",
					Usage: "fetch a KeyInit message",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.fetchKeyInit(c.String("id"))
					},
				},
				{
					Name:  "flush",
					Usage: "flush KeyInit messages",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.flushKeyInit(c.String("id"))
					},
				},
			},
		},
		{
			Name:  "hashchain",
			Usage: "commands for hash chain operations",
			Subcommands: []cli.Command{
				{
					Name:  "sync",
					Usage: "sync hash chain with key server",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "domain",
							Usage: "key server domain",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("domain") {
							return log.Error("option --domain is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.syncHashChain(c.String("domain"))
					},
				},
				{
					Name:  "validate",
					Usage: "validate local hash chain",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "domain",
							Usage: "key server domain",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("domain") {
							return log.Error("option --domain is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.validateHashChain(c.String("domain"))
					},
				},
				{
					Name:  "search",
					Usage: "search local hash chain",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.searchHashChain(c.String("id"))
					},
				},

				{
					Name:  "lookup",
					Usage: "lookup ID on key server",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "user ID",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.lookupHashChain(c.String("id"))
					},
				},
			},
		},
		{
			Name:  "encrypt",
			Usage: "encrypt message",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "from",
					Usage: "user ID to send from",
				},
				cli.StringFlag{
					Name:  "to",
					Usage: "user ID to send to",
				},
				cli.BoolFlag{
					Name:  "sign",
					Usage: "sign message with permanent signature",
				},
			},
			Before: func(c *cli.Context) error {
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				if !c.IsSet("from") {
					return log.Error("option --from is mandatory")
				}
				if !c.IsSet("to") {
					return log.Error("option --to is mandatory")
				}
				if err := ce.prepare(c, true); err != nil {
					return err
				}
				return nil
			},
			Action: func(c *cli.Context) {
				inputfp := os.NewFile(uintptr(c.GlobalInt("input-fd")), "input-fd")
				outputfp := os.NewFile(uintptr(c.GlobalInt("output-fd")), "output-fd")
				statusfp := os.NewFile(uintptr(c.GlobalInt("status-fd")), "status-fd")
				ce.err = ce.encrypt(outputfp, c.String("from"), c.String("to"),
					c.Bool("sign"), inputfp, statusfp)
			},
		},
		{
			Name:  "decrypt",
			Usage: "decrypt message",
			Before: func(c *cli.Context) error {
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				if err := ce.prepare(c, true); err != nil {
					return err
				}
				return nil
			},
			Action: func(c *cli.Context) {
				inputfp := os.NewFile(uintptr(c.GlobalInt("input-fd")), "input-fd")
				outputfp := os.NewFile(uintptr(c.GlobalInt("output-fd")), "output-fd")
				statusfp := os.NewFile(uintptr(c.GlobalInt("status-fd")), "status-fd")
				ce.err = ce.decrypt(outputfp, inputfp, statusfp)
			},
		},
		{
			Name:  "quit",
			Usage: "end program",
			Before: func(c *cli.Context) error {
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				if err := ce.prepare(c, false); err != nil {
					return err
				}
				return nil
			},
			Action: func(c *cli.Context) {
				ce.err = errExit
			},
		},
	}
	ce.cache = cache.New()
	return &ce
}

// Start starts the crypt engine with the given args.
func (ce *CryptEngine) Start(args []string) error {
	defer ce.Close()
	ce.app.Name = args[0]
	if err := ce.app.Run(args); err != nil {
		return err
	}
	if ce.err != nil {
		return ce.err
	}
	return nil
}

func (ce *CryptEngine) openKeyDB(passfd int) error {
	// read passphrase
	log.Infof("read passphrase from fd %d", passfd)
	passphrase, err := util.Readline(passfd, "passphrase-fd")
	if err != nil {
		return err
	}
	defer bzero.Bytes(passphrase)
	log.Info("done")
	// open keyDB
	keydbname := path.Join(ce.homedir, "keys")
	log.Infof("open keyDB %s", keydbname)
	ce.keyDB, err = keydb.Open(keydbname, passphrase)
	if err != nil {
		return err
	}
	return nil
}

// Close the underlying database of the crypt engine.
func (ce *CryptEngine) Close() error {
	if ce.keyDB != nil {
		err := ce.keyDB.Close()
		ce.keyDB = nil
		return err
	}
	return nil
}
