// muteproto implements the Mute message protocol for sending and receiving
// encrypted messages.
package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/protoengine"
	"github.com/mutecomm/mute/release"
	"github.com/mutecomm/mute/util"
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
