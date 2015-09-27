// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ctrlengine implements the command engine for mutectrl.
package ctrlengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/agl/ed25519"
	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/configclient"
	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msgdb"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/serviceguard/client/trivial"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/bzero"
	"github.com/mutecomm/mute/util/home"
	"github.com/peterh/liner"
)

// possible states
const (
	startState = iota
	noDBs
	lockedDBs
	emptyDBs
	unlockedDBs
	lockedDaemon
	composingMsg
)

var (
	defaultHomeDir = home.AppDataDir("mute", false)
	defaultLogDir  = path.Join(defaultHomeDir, "log")
	errExit        = errors.New("cryptengine: requests exit")
)

// CtrlEngine abstracts a mutectrl command engine.
type CtrlEngine struct {
	prepared   bool
	state      int
	msgDB      *msgdb.MsgDB
	passphrase []byte
	app        *cli.App
	client     *client.Client // service guard client
	err        error
	config     configclient.Config
}

func startWallet(msgDB *msgdb.MsgDB, offline bool) (*client.Client, error) {
	// get wallet key
	wk, err := msgDB.GetValue(msgdb.WalletKey)
	if err != nil {
		return nil, err
	}
	walletKey, err := decodeWalletKey(wk)
	if err != nil {
		return nil, err
	}

	// TODO: make this configurable

	// create wallet
	client, err := trivial.New(msgDB.DB(), walletKey, def.CACert)
	if err != nil {
		return nil, err
	}
	if !offline {
		client.GoOnline()
		err = client.GetVerifyKeys()
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (ce *CtrlEngine) prepare(c *cli.Context, openMsgDB bool) error {
	if !ce.prepared {
		// create the necessary directories if they don't already exist
		err := util.CreateDirs(c.GlobalString("homedir"), c.GlobalString("logdir"))
		if err != nil {
			return err
		}

		err = log.Init(c.GlobalString("loglevel"), "ctrl ",
			c.GlobalString("logdir"), c.GlobalBool("logconsole"))
		if err != nil {
			return err
		}

		ce.prepared = true
	}

	// open MsgDB, if necessary
	offline := c.GlobalBool("offline")
	if openMsgDB {
		if ce.msgDB == nil {
			err := ce.openMsgDB(c.GlobalString("homedir"),
				c.GlobalInt("passphrase-fd"), c.GlobalInt("status-fd"))
			if err != nil {
				return err
			}
		}

		// read default config
		jsn, err := ce.msgDB.GetValue(def.DefaultDomain)
		if err != nil {
			return err
		}
		if jsn != "" {
			if err := json.Unmarshal([]byte(jsn), &ce.config); err != nil {
				return err
			}
			// apply new configuration
			if err := def.InitMute(&ce.config); err != nil {
				return err
			}
		} else {
			// no config found, fetch it
			if offline {
				return log.Error("ctrlengine: cannot fetch in --offline mode")
			}
			statfp := os.NewFile(uintptr(c.Int("status-fd")), "status-fd")
			fmt.Fprintf(statfp, "no system config found")
			err := ce.upkeepFetchconf(ce.msgDB, c.GlobalString("homedir"),
				false, nil, statfp)
			if err != nil {
				return err
			}
		}

		// start wallet
		ce.client, err = startWallet(ce.msgDB, offline)
		if err != nil {
			return err
		}
	}

	return nil
}

func buildCmdList(commands []cli.Command, prefix string) []string {
	var cmds []string
	for _, cmd := range commands {
		if cmd.Subcommands != nil {
			cmds = append(cmds, buildCmdList(cmd.Subcommands, cmd.Name+" ")...)
		} else {
			cmds = append(cmds, prefix+cmd.Name)
		}
	}
	return cmds
}

var (
	interactive bool
	line        *liner.State
)

// loop runs the CtrlEngine in a loop and reads commands from the file
// descriptor command-fd.
func (ce *CtrlEngine) loop(c *cli.Context) {
	if len(c.Args()) > 0 {
		ce.err = fmt.Errorf("ctrlengine: unknown command '%s', try 'help'",
			strings.Join(c.Args(), " "))
		return
	}

	log.Info("ctrlengine: starting")

	interactive = true

	// run command(s)
	statusfp := os.NewFile(uintptr(c.Int("status-fd")), "status-fd")
	line = liner.NewLiner()
	defer line.Close()
	line.SetCtrlCAborts(true)
	commands := buildCmdList(c.App.Commands, "")
	line.SetCompleter(func(line string) (c []string) {
		for _, command := range commands {
			if strings.HasPrefix(command, line) {
				c = append(c, command)
			}
		}
		return
	})

	for {
		active, err := ce.msgDB.GetValue(msgdb.ActiveUID)
		if err != nil {
			util.Fatal(err)
		}
		if active == "" {
			active = "none"
		}
		fmt.Fprintf(statusfp, "active user ID: %s\n", active)
		fmt.Fprintln(statusfp, "READY.")
		ln, err := line.Prompt("")
		if err != nil {
			if err == liner.ErrPromptAborted {
				fmt.Fprintf(statusfp, "aborting...\n")
			}
			log.Info("ctrlengine: stopping (error)")
			log.Error(err)
			return
		}
		line.AppendHistory(ln)

		args := []string{ce.app.Name}
		if ln == "" {
			log.Infof("read empty line")
			continue
		}
		log.Infof("read: %s", ln)
		args = append(args, strings.Fields(ln)...)
		if err := ce.app.Run(args); err != nil {
			// command execution failed -> issue status and continue
			log.Infof("command execution failed (app): %s", err)
			fmt.Fprintln(statusfp, err)
			continue
		}
		if ce.err != nil {
			if ce.err == errExit {
				// exit requested -> return
				log.Info("ctrlengine: stopping (exit requested)")
				ce.err = nil
				return
			}
			// command execution failed -> issue status and continue
			fmt.Fprintln(statusfp, ce.err)
			ce.err = nil
		} else {
			log.Info("command successful")
		}
	}
}

func (ce *CtrlEngine) getID(c *cli.Context) string {
	id := c.String("id")
	if id == "" && interactive {
		active, err := ce.msgDB.GetValue(msgdb.ActiveUID)
		if err != nil {
			panic(log.Critical(err))
		}
		id = active
	}
	return id
}

func checkDelayArgs(c *cli.Context) error {
	if c.Int("mindelay") < def.MinMinDelay {
		return log.Errorf("--mindelay must be at least %d", def.MinMinDelay)
	}
	if c.Int("maxdelay") < def.MinMaxDelay {
		return log.Errorf("--maxdelay must be at least %d", def.MinMaxDelay)
	}
	if c.Int("mindelay") >= c.Int("maxdelay") {
		return log.Error("--mindelay must be strictly smaller than --maxdelay")
	}
	return nil
}

// New returns a new CtrlEngine.
func New() *CtrlEngine {
	var ce CtrlEngine
	ce.app = cli.NewApp()
	ce.app.Usage = "tool that handles message DB, contacts, and tokens."
	ce.app.Version = def.Version
	ce.app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "homedir",
			Value: defaultHomeDir,
			Usage: "set home directory",
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
		cli.BoolFlag{
			Name:  "offline",
			Usage: "use offline mode",
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
	ce.app.After = func(c *cli.Context) error {
		// TODO: close all file descriptors?
		/*
			os.NewFile(uintptr(c.Int("input-fd")), "input-fd").Close()
			os.NewFile(uintptr(c.Int("status-fd")), "status-fd").Close()
			os.NewFile(uintptr(c.Int("passphrase-fd")), "passphrase-fd").Close()
			os.NewFile(uintptr(c.Int("command-fd")), "command-fd").Close()
			os.NewFile(uintptr(c.Int("output-fd")), "output-fd").Close()
		*/
		return nil
	}
	ce.app.Action = func(c *cli.Context) {
		if err := ce.prepare(c, true); err != nil {
			util.Fatal(err)
		}
		ce.loop(c)
	}
	idFlag := cli.StringFlag{
		Name:  "id",
		Usage: "user ID (self)",
	}
	allFlag := cli.BoolFlag{
		Name:  "all",
		Usage: "perform action for all user IDs (bad for anonymity!)",
	}
	contactFlag := cli.StringFlag{
		Name:  "contact",
		Usage: "user ID of contact (peer)",
	}
	fullNameFlag := cli.StringFlag{
		Name:  "full-name",
		Usage: "optional full name for user ID (local)",
	}
	hostFlag := cli.StringFlag{
		Name:  "host",
		Usage: "alternative hostname",
	}
	mindelayFlag := cli.IntFlag{
		Name:  "mindelay",
		Value: int(def.MinDelay),
		Usage: fmt.Sprintf("minimum delay for mix (min. %ds)", def.MinMinDelay),
	}
	maxdelayFlag := cli.IntFlag{
		Name:  "maxdelay",
		Value: int(def.MaxDelay),
		Usage: fmt.Sprintf("maximum delay for mix (min. %ds)", def.MinMaxDelay),
	}
	ce.app.Commands = []cli.Command{
		{
			Name:  "db",
			Usage: "Commands for local databases",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "Create databases",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "iterations",
							Value: def.KDFIterationsDB,
							Usage: "number of KDF iterations used for DB creation",
						},
						cli.StringFlag{
							Name:  "walletkey",
							Usage: "use this private wallet key instead of generated one",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						return ce.prepare(c, false)
					},
					Action: func(c *cli.Context) {
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						statusfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.dbCreate(outfp, statusfp,
							c.GlobalString("homedir"), c)
					},
				},
				{
					Name:  "rekey",
					Usage: "Rekey databases",
					Flags: []cli.Flag{
						cli.IntFlag{
							Name:  "iterations",
							Value: def.KDFIterationsDB,
							Usage: "number of KDF iterations used for DB rekeying",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						return ce.prepare(c, false)
					},
					Action: func(c *cli.Context) {
						statusfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.dbRekey(statusfp, c)
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
						ce.err = ce.dbStatus(c, outputfp)
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
						ce.err = ce.dbVacuum(c, c.String("auto-vacuum"))
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
						ce.err = ce.dbIncremental(c, int64(c.Int("pages")))
					},
				},
			},
		},
		{
			Name:  "uid",
			Usage: "Commands for user IDs",
			Subcommands: []cli.Command{
				{
					Name:  "new",
					Usage: "register a new user ID",
					Description: `
Tries to register a new user ID with the corresponding key server.
`,
					Flags: []cli.Flag{
						idFlag,
						fullNameFlag,
						hostFlag,
						mindelayFlag,
						maxdelayFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := checkDelayArgs(c); err != nil {
							return err
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.uidNew(c, int32(c.Int("mindelay")),
							int32(c.Int("maxdelay")))
					},
				},
				{
					Name:  "edit",
					Usage: "edit an existing user ID",
					Flags: []cli.Flag{
						idFlag,
						fullNameFlag,
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
						ce.err = ce.uidEdit(c.String("id"), c.String("full-name"))
					},
				},
				{
					Name:  "active",
					Usage: "show active user ID",
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
						ce.err = ce.uidActive(c)
					},
				},
				{
					Name:  "switch",
					Usage: "switch active user ID",
					Flags: []cli.Flag{
						idFlag,
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
						ce.err = ce.uidSwitch(c.String("id"))
					},
				},
				{
					Name:  "delete",
					Usage: "delete own user ID",
					Flags: []cli.Flag{
						idFlag,
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
						statfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.uidDelete(c, c.String("id"), c.Bool("force"), statfp)
					},
				},
				{
					Name:  "list",
					Usage: "list own (unmapped) user IDs",
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
						ce.err = ce.uidList(outfp)
					},
				},
			},
		},
		{
			Name:  "contact",
			Usage: "Commands for contact management",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "add new contact to active user ID (-> white list)",
					Description: `
Tries to register a new user ID with the corresponding key server.
`,
					Flags: []cli.Flag{
						idFlag,
						contactFlag,
						fullNameFlag,
						hostFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("contact") {
							return log.Error("option --contact is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.contactAdd(ce.getID(c), c.String("contact"),
							c.String("full-name"), c.String("host"),
							msgdb.WhiteList, c)
					},
				},
				{
					Name:  "edit",
					Usage: "edit contact entry of active user ID",
					Flags: []cli.Flag{
						idFlag,
						contactFlag,
						fullNameFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("contact") {
							return log.Error("option --contact is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.contactEdit(ce.getID(c),
							c.String("contact"), c.String("full-name"))
					},
				},
				{
					Name:  "remove",
					Usage: "remove contact for active user ID (-> gray list)",
					Description: `
Tries to register a new user ID with the corresponding key server.
`,
					Flags: []cli.Flag{
						idFlag,
						contactFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("contact") {
							return log.Error("option --contact is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.contactRemove(ce.getID(c),
							c.String("contact"))
					},
				},
				{
					Name:  "block",
					Usage: "block contact for active user ID (-> black list)",
					Description: `
Tries to register a new user ID with the corresponding key server.
`,
					Flags: []cli.Flag{
						idFlag,
						contactFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("contact") {
							return log.Error("option --contact is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.contactBlock(ce.getID(c),
							c.String("contact"))
					},
				},
				{
					Name:  "unblock",
					Usage: "unblock contact for active user ID (-> white list)",
					Description: `
Tries to register a new user ID with the corresponding key server.
`,
					Flags: []cli.Flag{
						idFlag,
						contactFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("contact") {
							return log.Error("option --contact is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.contactUnblock(ce.getID(c),
							c.String("contact"))
					},
				},
				{
					Name:  "list",
					Usage: "list contacts for active user ID (white list)",
					Flags: []cli.Flag{
						idFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.contactList(outfp, ce.getID(c))
					},
				},
				{
					Name:  "blacklist",
					Usage: "list blocked contacts for active user ID (black list)",
					Flags: []cli.Flag{
						idFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.contactBlacklist(outfp, ce.getID(c))
					},
				},
			},
		},
		{
			Name:  "msg",
			Usage: "Commands for message processing",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "add a new message to out queue",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "from, id",
							Usage: "user ID to send message from",
						},
						cli.StringFlag{
							Name:  "to",
							Usage: "user ID to send message to",
						},
						cli.StringFlag{
							Name:  "file",
							Usage: "read message from file",
						},
						cli.StringSliceFlag{
							Name:  "attach",
							Usage: "file to append as attachment",
						},
						cli.BoolFlag{
							Name:  "permanent-signature",
							Usage: "add permanent sign. to message",
						},
						mindelayFlag,
						maxdelayFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("from") {
							return log.Error("option --from is mandatory")
						}
						if !c.IsSet("to") {
							return log.Error("option --to is mandatory")
						}
						if err := checkDelayArgs(c); err != nil {
							return err
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						inputfp := os.NewFile(uintptr(c.GlobalInt("input-fd")),
							"input-fd")
						ce.err = ce.msgAdd(c, ce.getID(c), c.String("to"),
							c.String("file"), c.Bool("permanent-signature"),
							c.StringSlice("attach"),
							int32(c.Int("mindelay")), int32(c.Int("maxdelay")),
							line, inputfp)
					},
				},
				{
					Name:  "send",
					Usage: "send messages from out queue",
					Flags: []cli.Flag{
						idFlag,
						allFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("all") && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.msgSend(c, ce.getID(c), c.Bool("all"))
					},
				},
				{
					Name:  "fetch",
					Usage: "fetch new messages and decrypt them",
					Flags: []cli.Flag{
						idFlag,
						allFlag,
						hostFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("all") && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						ce.err = ce.msgFetch(c, ce.getID(c), c.Bool("all"),
							c.String("host"))
					},
				},
				{
					Name:  "list",
					Usage: "list messages",
					Flags: []cli.Flag{
						idFlag,
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outputfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.msgList(outputfp, ce.getID(c))
					},
				},
				{
					Name:  "read",
					Usage: "read message",
					Flags: []cli.Flag{
						idFlag,
						cli.IntFlag{
							Name:  "msgid",
							Usage: "message ID to read",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("msgid") {
							return log.Error("option --msgid is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outputfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.msgRead(outputfp, ce.getID(c),
							int64(c.Int("msgid")))
					},
				},
			},
		},
		{
			Name:  "upkeep",
			Usage: "Commands for upkeep (maintenance)",
			Subcommands: []cli.Command{
				{
					Name:  "all",
					Usage: "Perform all upkeep tasks for user ID",
					Flags: []cli.Flag{
						idFlag,
						cli.StringFlag{
							Name:  "period",
							Usage: "perform task only if last execution was earlier than period",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("period") {
							return log.Error("option --period is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						statfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.upkeepAll(c, ce.getID(c),
							c.String("period"), statfp)
					},
				},
				{
					Name:  "fetchconf",
					Usage: "Fetch current Mute system config",
					Flags: []cli.Flag{
						cli.BoolFlag{
							Name:  "show",
							Usage: "Show config on output-fp",
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
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						statfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.upkeepFetchconf(ce.msgDB,
							c.GlobalString("homedir"), c.Bool("show"), outfp,
							statfp)
					},
				},
				{
					Name:  "update",
					Usage: "Update Mute binaries (from source or download binaries)",
					/*
						Flags: []cli.Flag{
							cli.BoolFlag{
								Name:  "source",
								Usage: "Force update from source",
							},
							cli.BoolFlag{
								Name:  "binary",
								Usage: "Force binary update",
							},
						},
					*/
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						/*
							if c.Bool("source") && c.Bool("binary") {
								return log.Error("options --source and --binary exclude each other")
							}
						*/
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						statfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.upkeepUpdate(c.GlobalString("homedir"),
							/* c.Bool("source"), c.Bool("binary"), */
							outfp, statfp)
					},
				},
				{
					Name:  "accounts",
					Usage: "Renew accounts on server",
					Flags: []cli.Flag{
						idFlag,
						cli.StringFlag{
							Name:  "period",
							Usage: "perform task only if last execution was earlier than period",
						},
						cli.StringFlag{
							Name:  "remaining",
							Value: "2160h",
							Usage: "renew account only if remaining time is less than remaining",
						},
					},
					Before: func(c *cli.Context) error {
						if len(c.Args()) > 0 {
							return log.Errorf("superfluous argument(s): %s",
								strings.Join(c.Args(), " "))
						}
						if !interactive && !c.IsSet("id") {
							return log.Error("option --id is mandatory")
						}
						if !c.IsSet("period") {
							return log.Error("option --period is mandatory")
						}
						if err := ce.prepare(c, true); err != nil {
							return err
						}
						return nil
					},
					Action: func(c *cli.Context) {
						statfp := os.NewFile(uintptr(c.GlobalInt("status-fd")),
							"status-fd")
						ce.err = ce.upkeepAccounts(ce.getID(c),
							c.String("period"), c.String("remaining"), statfp)
					},
				},
			},
		},
		{
			Name:  "wallet",
			Usage: "Commands for wallet management",
			Subcommands: []cli.Command{
				{
					Name:  "pubkey",
					Usage: "Show public key of wallet",
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
						outfp := os.NewFile(uintptr(c.GlobalInt("output-fd")),
							"output-fd")
						ce.err = ce.walletPubkey(outfp)
					},
				},
			},
		},
		{
			Name:  "quit",
			Usage: "End program",
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
	return &ce
}

// Start starts the CtrlEngine with the given args.
func (ce *CtrlEngine) Start(args []string) error {
	ce.app.Name = args[0]
	if err := ce.app.Run(args); err != nil {
		return err
	}
	if ce.err != nil {
		return ce.err
	}
	return nil
}

// TODO: extract method
func decodeWalletKey(p string) (*[ed25519.PrivateKeySize]byte, error) {
	var ret [ed25519.PrivateKeySize]byte
	pd, err := base64.Decode(p)
	if err != nil {
		return nil, err
	}
	copy(ret[:], pd)
	return &ret, nil
}

func (ce *CtrlEngine) openMsgDB(
	homedir string,
	passfd, statusfd int,
) error {
	// read passphrase
	statusfp := os.NewFile(uintptr(statusfd), "status-fd")
	fmt.Fprintf(statusfp, "read passphrase from fd %d\n", passfd)
	log.Infof("read passphrase from fd %d", passfd)
	var err error
	ce.passphrase, err = util.Readline(passfd, "passphrase-fd")
	if err != nil {
		return err
	}
	log.Info("done")
	// TODO: close passphrase-fd after reading from it?
	// rekey probably doesn't work anymore
	// os.NewFile(uintptr(passfd), "").Close()

	// open msgDB
	msgdbname := path.Join(homedir, "msgs")
	log.Infof("open msgDB %s", msgdbname)
	ce.msgDB, err = msgdb.Open(msgdbname, ce.passphrase)
	if err != nil {
		return err
	}
	return nil
}

// Close the underlying database of the CtrlEngine.
func (ce *CtrlEngine) Close() {
	if ce.msgDB != nil {
		// stop service guard client before we close the DB
		if ce.client != nil {
			ce.client.GoOffline()
		}
		ce.msgDB.Close()
		ce.msgDB = nil
	}
	bzero.Bytes(ce.passphrase)
}
