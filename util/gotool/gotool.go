// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gotool implements wrappers for the Go tool.
package gotool

import (
	"io"
	"os/exec"
)

// Generate executes `go generate -v` in directory dir.
func Generate(dir, arg string, outfp, statfp io.Writer) error {
	cmd := exec.Command("go", "generate", "-v", arg)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = outfp
	cmd.Stderr = statfp
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Install executes `go install -v` in directory dir.
func Install(dir, arg string, outfp, statfp io.Writer) error {
	cmd := exec.Command("go", "install", "-v", arg)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = outfp
	cmd.Stderr = statfp
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
