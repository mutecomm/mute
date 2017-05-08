// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package release implements release specific constants and methods.
package release

import (
	"fmt"
	"math/big"

	"github.com/urfave/cli"
)

//go:generate mutegenerate -o head.go

// PrintVersion prints version information.
func PrintVersion(c *cli.Context) {
	fmt.Fprintf(c.App.Writer, "%v version %v\n", c.App.Name, c.App.Version)
	fmt.Fprintf(c.App.Writer, "commit %s\n", Commit)
	fmt.Fprintf(c.App.Writer, "Date:   %s\n", Date)
}

// Hack to enforce that we compile with at least Go 1.5.
// We need Go 1.5 (with environment variable GO15VENDOREXPERIMENT set to 1) to
// enforce compiling with the sources in vendor/ instead of pulling in external
// libraries. Otherwise it is impossible to make any security guarantees.
var _ big.Float
