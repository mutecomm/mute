// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// mutecrypt is the crypt tool for Mute which handles message encryption, message decryption and key management.
package main

import (
	"os"

	"github.com/mutecomm/mute/cryptengine"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/release"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/interrupt"
	"github.com/urfave/cli"
)

func init() {
	cli.VersionPrinter = release.PrintVersion
}

func mutecryptMain() error {
	defer log.Flush()

	// create crypto engine
	ce := cryptengine.New()
	defer ce.Close()

	// add interrupt handler
	interrupt.AddInterruptHandler(func() {
		log.Infof("gracefully shutting down...")
		ce.Close()
	})

	// start crypto engine
	go func() {
		if err := ce.Start(os.Args); err != nil {
			interrupt.ShutdownChannel <- err
			return
		}
		interrupt.ShutdownChannel <- nil
	}()

	return <-interrupt.ShutdownChannel
}

func main() {
	// work around defer not working after os.Exit()
	if err := mutecryptMain(); err != nil {
		util.Fatal(err)
	}
}
