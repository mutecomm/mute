// Package release implements release specific constants and methods.
package release

import (
	"fmt"

	"github.com/codegangsta/cli"
)

//go:generate mutegenerate -o head.go

// PrintVersion prints version information.
func PrintVersion(c *cli.Context) {
	fmt.Fprintf(c.App.Writer, "%v version %v\n", c.App.Name, c.App.Version)
	fmt.Fprintf(c.App.Writer, "commit %s\n", Commit)
	fmt.Fprintf(c.App.Writer, "Date:   %s\n", Date)
}
