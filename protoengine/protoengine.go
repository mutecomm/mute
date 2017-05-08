// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package protoengine implements the command engine for muteproto.
package protoengine

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/def/version"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/descriptors"
	"github.com/mutecomm/mute/util/home"
	"github.com/urfave/cli"
)

const (
	nodb     = "no keyDB"
	locked   = "locked keyDB"
	unlocked = "unlocked keyDB"
)

var (
	defaultHomeDir = home.AppDataDir("mute", false)
	defaultLogDir  = filepath.Join(defaultHomeDir, "log")
	errExit        = errors.New("cryptengine: requests exit")
)

// ProtoEngine abstracts a muteproto command engine.
type ProtoEngine struct {
	fileTable *descriptors.Table
	accdHost  string
	accdPort  string
	homedir   string
	app       *cli.App
	err       error
}

func (pe *ProtoEngine) prepare(c *cli.Context) error {
	pe.accdHost = c.GlobalString("acchost")
	pe.accdPort = c.GlobalString("accport")
	pe.homedir = c.GlobalString("homedir")

	// create the necessary directories if they don't already exist
	err := util.CreateDirs(c.GlobalString("homedir"), c.GlobalString("logdir"))
	if err != nil {
		return err
	}

	// initialize logging framework
	err = log.Init(c.GlobalString("loglevel"), "proto",
		c.GlobalString("logdir"), c.GlobalBool("logconsole"))
	if err != nil {
		return err
	}

	// initialize file descriptors
	pe.fileTable, err = descriptors.NewTable(c)
	if err != nil {
		return err
	}

	// configure
	if err := def.InitMuteFromFile(pe.homedir); err != nil {
		return err
	}

	return nil
}

// New returns a new Mute proto engine.
func New() *ProtoEngine {
	var pe ProtoEngine
	pe.app = cli.NewApp()
	pe.app.Usage = "tool to handle message delivery and retrieval"
	pe.app.Version = version.Number
	pe.app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "homedir",
			Value: defaultHomeDir,
			Usage: "set home directory",
		},
		cli.StringFlag{
			Name:  "acchost",
			Usage: "alternative hostname for account server",
		},
		descriptors.InputFDFlag,
		descriptors.OutputFDFlag,
		descriptors.StatusFDFlag,
		descriptors.PassphraseFDFlag,
		descriptors.CommandFDFlag,
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
	pe.app.Before = func(c *cli.Context) error {
		return pe.prepare(c)
	}
	pe.app.Commands = []cli.Command{
		{
			Name:  "create",
			Usage: "create envelope message from an encrypted message",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "mindelay",
					Value: int(def.MinDelay),
					Usage: "minimum sender delay (for mix)",
				},
				cli.IntFlag{
					Name:  "maxdelay",
					Value: int(def.MaxDelay),
					Usage: "maximum sender delay (for mix)",
				},
				cli.StringFlag{
					Name:  "token",
					Usage: "payment token (for mix)",
				},
				cli.StringFlag{
					Name:  "nymaddress",
					Usage: "nymaddress of recipient",
				},
			},
			Before: func(c *cli.Context) error {
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				if !c.IsSet("token") {
					return log.Error("option --token is mandatory")
				}
				if !c.IsSet("nymaddress") {
					return log.Error("option --nymaddress is mandatory")
				}
				return nil
			},
			Action: func(c *cli.Context) {
				pe.err = pe.create(pe.fileTable.OutputFP,
					int32(c.Int("mindelay")), int32(c.Int("maxdelay")),
					c.String("token"), c.String("nymaddress"),
					pe.fileTable.InputFP)
			},
		},
		{
			Name:  "deliver",
			Usage: "deliver envelope message to corresponding mix",
			Before: func(c *cli.Context) error {
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				return nil
			},
			Action: func(c *cli.Context) {
				pe.err = pe.deliver(pe.fileTable.StatusFP, pe.fileTable.InputFP)
			},
		},
		{
			Name:  "fetch",
			Usage: "fetch new messages from server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "server",
					Usage: "server to fetch messages from",
				},
				cli.StringFlag{
					Name:  "last-message-time",
					Usage: "time of the last read message",
				},
			},
			Before: func(c *cli.Context) error {
				if !c.IsSet("server") {
					return log.Error("option --server is mandatory")
				}
				if len(c.Args()) > 0 {
					return log.Errorf("superfluous argument(s): %s", strings.Join(c.Args(), " "))
				}
				return nil
			},
			Action: func(c *cli.Context) {
				pe.err = pe.fetch(pe.fileTable.OutputFP, pe.fileTable.StatusFP,
					c.String("server"), int64(c.Int("last-message-time")),
					pe.fileTable.CommandFP)
			},
		},
	}
	return &pe
}

// Run runs the proto engine with the given args.
func (pe *ProtoEngine) Run(args []string) error {
	pe.app.Name = args[0]
	if err := pe.app.Run(args); err != nil {
		return err
	}
	if pe.err != nil {
		return pe.err
	}
	return nil
}
