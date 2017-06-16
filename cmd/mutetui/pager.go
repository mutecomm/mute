// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io/ioutil"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/views"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/tui/editor"
	"github.com/urfave/cli"
)

var pagerCommand = cli.Command{
	Name:      "pager",
	Usage:     "Page given file",
	ArgsUsage: "filename",
	Before: func(c *cli.Context) error {
		if len(c.Args()) < 1 {
			return errors.New("missing filename argument")
		}
		return checkSuperfluousArgs(c, 1)
	},
	Action: func(c *cli.Context) error {
		return pager(c.Args().First())
	},
}

type root struct {
	app *views.Application
	editor.Editor
}

func (r *root) HandleEvent(ev tcell.Event) bool {
	log.Trace("root.HandleEvent()")
	switch ev := ev.(type) {
	case *tcell.EventKey:
		switch ev.Key() {
		case tcell.KeyCtrlL:
			r.app.Refresh()
			return true
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'Q', 'q':
				r.app.Quit()
				return true
			case 'i':
				r.Editor.EnableCursor(true)
				r.Editor.MakeCursorVisible()
				return true
			}
		}
	}
	log.Trace("calling r.TextArea.HandleEvent()")
	return r.Editor.HandleEvent(ev)
}

func (r *root) Draw() {
	r.Editor.Draw()
}

func pager(filename string) error {
	log.Trace("main.pager()")
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	app := &views.Application{}
	app.SetStyle(tcell.StyleDefault.
		Foreground(tcell.ColorBlack).
		Background(tcell.ColorWhite))

	root := &root{app: app}
	root.Editor.SetContent(buf)

	app.SetRootWidget(root)
	if err := app.Run(); err != nil {
		return err
	}
	return nil
}
