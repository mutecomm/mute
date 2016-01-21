// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package browser

import (
	"os/exec"
	"runtime"
)

// Start tries to open the URL in a browser
// and reports whether it succeeds.
// Note: copied startBrowser from
// https://github.com/golang/go/blob/master/src/cmd/cover/html.go
func Start(url string) bool {
	// try to start the browser
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"open"}
	case "windows":
		args = []string{"cmd", "/c", "start"}
	default:
		args = []string{"xdg-open"}
	}
	cmd := exec.Command(args[0], append(args[1:], url)...)
	return cmd.Start() == nil
}
