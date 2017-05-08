// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// muteproto implements the Mute message protocol for sending and receiving
// encrypted messages.
package main

import (
	"os"

	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/protoengine"
	"github.com/mutecomm/mute/release"
	"github.com/mutecomm/mute/util"
	"github.com/urfave/cli"
)

func init() {
	cli.VersionPrinter = release.PrintVersion
}

func muteprotoMain() error {
	defer log.Flush()

	// create proto engine
	pe := protoengine.New()

	// run proto engine
	if err := pe.Run(os.Args); err != nil {
		return err
	}
	return nil
}

func main() {
	// work around defer not working after os.Exit()
	if err := muteprotoMain(); err != nil {
		util.Fatal(err)
	}
}
