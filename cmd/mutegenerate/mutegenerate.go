// mutegenerate can be used by go:generate to generate code that includes the
// current git HEAD commit hash and date as constants.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mutecomm/mute/util/git"
)

func printCode(w io.Writer, release bool, commit, date string) {
	if release {
		fmt.Fprintf(w, "  \"release.Commit\": \"%s\",\n", commit)
		fmt.Fprintf(w, "  \"release.Date\": \"%s\"\n", date)
	} else {
		fmt.Fprintf(w, "package release\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "// This code has been generated by mutegenerate.\n")
		fmt.Fprintf(w, "// DO NOT EDIT AND DO NOT COMMIT TO REPOSITORY!\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "const (\n")
		fmt.Fprintf(w, "\tCommit = \"%s\"\n", commit)
		fmt.Fprintf(w, "\tDate   = \"%s\"\n", date)
		fmt.Fprintf(w, ")\n")
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "%s: error: %s\n", os.Args[0], err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	output := flag.String("o", "", "write generated code to file")
	release := flag.Bool("r", false, "write output for release (server config format)")
	test := flag.Bool("t", false, "just exit with status code 0 (test if binary exists)")
	flag.Parse()
	if flag.NArg() != 0 {
		usage()
	}
	if *test {
		return
	}
	commit, date, err := git.GetHead("", os.Stderr)
	if err != nil {
		fatal(err)
	}
	outfp := os.Stdout
	if *output != "" {
		outfp, err = os.Create(*output)
		if err != nil {
			fatal(err)
		}
	}
	printCode(outfp, *release, commit, date)
}
