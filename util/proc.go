// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"os"
	"os/exec"
	"runtime"
)

// StopProc interrupts a process and waits until it exits.
// On windows, interrupt is not supported, so a kill signal is used instead.
func StopProc(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	defer cmd.Wait()
	if runtime.GOOS == "windows" {
		return cmd.Process.Signal(os.Kill)
	}
	return cmd.Process.Signal(os.Interrupt)
}
