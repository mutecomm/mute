// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package descriptors defines helper functions for common file descriptors.
package descriptors

import (
	"os"
	"strconv"
	"syscall"

	"github.com/mutecomm/mute/log"
	"github.com/urfave/cli"
)

var (
	// InputFDFlag defines the standard --input-fd flag.
	InputFDFlag = cli.StringFlag{
		Name:  "input-fd",
		Value: "stdin",
		Usage: "input file descriptor",
	}
	// OutputFDFlag defines the standard --output-fd flag.
	OutputFDFlag = cli.StringFlag{
		Name:  "output-fd",
		Value: "stdout",
		Usage: "output file descriptor",
	}
	// StatusFDFlag defines the standard --status-fd flag.
	StatusFDFlag = cli.StringFlag{
		Name:  "status-fd",
		Value: "stderr",
		Usage: "status file descriptor",
	}
	// PassphraseFDFlag defines the standard --passphrase-fd flag.
	PassphraseFDFlag = cli.StringFlag{
		Name:  "passphrase-fd",
		Value: "3",
		Usage: "passphrase file descriptor",
	}
	// CommandFDFlag defines the standard --command-fd flag.
	CommandFDFlag = cli.StringFlag{
		Name:  "command-fd",
		Value: "4",
		Usage: "command file descriptor",
	}
)

// Table contains all standard file descriptors and file pointers.
type Table struct {
	InputFD      uintptr  // input file descriptor
	OutputFD     uintptr  // output file descriptor
	StatusFD     uintptr  // status file descriptor
	PassphraseFD uintptr  // passphrase file descriptor
	CommandFD    uintptr  // command file descriptor
	InputFP      *os.File // input file pointer
	OutputFP     *os.File // output file pointer
	StatusFP     *os.File // status file pointer
	PassphraseFP *os.File // passphrase file pointer
	CommandFP    *os.File // command file pointer
}

func parseFDOption(c *cli.Context, name string) (
	fd uintptr,
	fp *os.File,
	err error,
) {
	fs := c.GlobalString(name)
	switch fs {
	case "stdin":
		fd = uintptr(syscall.Stdin)
		fp = os.Stdin
	case "stdout":
		fd = uintptr(syscall.Stdout)
		fp = os.Stdout
	case "stderr":
		fd = uintptr(syscall.Stderr)
		fp = os.Stderr
	default:
		i, err := strconv.Atoi(fs)
		if err != nil {
			return 0, nil,
				log.Errorf("cannot parse --%s %s: argument must be \"stdin\", "+
					"\"stdout\", \"stderr\" or an integer (a file descriptor)",
					name, fs)
		}
		fd = uintptr(i)
		fp = os.NewFile(fd, name)
	}
	return
}

// NewTable parses the standard file descriptor options in context c and
// returns a table with the corresponding file descriptors and file pointers.
func NewTable(c *cli.Context) (*Table, error) {
	var t Table
	var err error
	t.InputFD, t.InputFP, err = parseFDOption(c, "input-fd")
	if err != nil {
		return nil, err
	}
	t.OutputFD, t.OutputFP, err = parseFDOption(c, "output-fd")
	if err != nil {
		return nil, err
	}
	t.StatusFD, t.StatusFP, err = parseFDOption(c, "status-fd")
	if err != nil {
		return nil, err
	}
	t.PassphraseFD, t.PassphraseFP, err = parseFDOption(c, "passphrase-fd")
	if err != nil {
		return nil, err
	}
	t.CommandFD, t.CommandFP, err = parseFDOption(c, "command-fd")
	if err != nil {
		return nil, err
	}
	return &t, nil
}
