// Package git implements git wrappers.
package git

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Date defines the layout of git dates useful for time.Parse.
const Date = "Mon Jan _2 15:04:05 2006 -0700"

// GetHead returns the commit and date of the git HEAD in the directory dir.
// If dir is nil, the current working directory of the calling binary is used.
func GetHead(dir string, statfp io.Writer) (commit, date string, err error) {
	cmd := exec.Command("git", "log", "-1", "--format=%H %ad")
	if dir != "" {
		cmd.Dir = dir
	}
	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	cmd.Stderr = statfp
	if err := cmd.Run(); err != nil {
		return "", "", err
	}
	parts := strings.SplitN(outbuf.String(), " ", 2)
	commit = parts[0]
	date = strings.TrimSpace(parts[1])
	return
}

// Status executes a `git status --porcelain` in directory dir.
func Status(dir string, statfp io.Writer) error {
	cmd := exec.Command("git", "status", "--porcelain")
	if dir != "" {
		cmd.Dir = dir
	}
	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	cmd.Stderr = statfp
	if err := cmd.Run(); err != nil {
		return err
	}
	if outbuf.String() != "" {
		return fmt.Errorf("git directory %s is not clean:\n%s", cmd.Dir,
			outbuf.String())
	}
	return nil
}

// Pull executes a `git pull` in directory dir.
func Pull(dir string, outfp, statfp io.Writer) error {
	cmd := exec.Command("git", "pull")
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = outfp
	cmd.Stderr = statfp
	return cmd.Run()
}

// Checkout executes a `git checkout commit` in directory dir.
func Checkout(dir, commit string, outfp, statfp io.Writer) error {
	cmd := exec.Command("git", "checkout", commit)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = outfp
	cmd.Stderr = statfp
	return cmd.Run()
}
