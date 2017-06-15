// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"

	"github.com/urfave/cli"
)

func checkSuperfluousArgs(c *cli.Context, num int) error {
	if len(c.Args()) > num {
		return fmt.Errorf("superfluous argument(s): %s",
			strings.Join(c.Args()[num:], " "))
	}
	return nil
}
