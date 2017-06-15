// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// mutetui is the text-based user interface (TUI) for Mute.
package main

import (
	"os"

	"github.com/mutecomm/mute/def/version"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/release"
	"github.com/mutecomm/mute/util"
	"github.com/urfave/cli"
)

func init() {
	cli.VersionPrinter = release.PrintVersion
}

func muteApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "Mute text-based user interface "
	app.Version = version.Number
	app.Commands = []cli.Command{
		pagerCommand,
	}
	return app
}

func mutetuiMain() error {
	defer log.Flush()
	return muteApp().Run(os.Args)
}

func main() {
	// work around defer not working after os.Exit()
	if err := mutetuiMain(); err != nil {
		util.Fatal(err)
	}
}
