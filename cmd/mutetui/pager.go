// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
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
	app    *views.Application
	editor *editor.Editor
	status *views.Text

	views.BoxLayout
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
				r.editor.EnableCursor(true)
				r.editor.MakeCursorVisible()
				return true
			}
		}
	}
	log.Trace("calling r.TextArea.HandleEvent()")
	return r.BoxLayout.HandleEvent(ev)
}

func (r *root) Draw() {
	r.BoxLayout.Draw()
}

type cursorEventHandler struct {
	text *views.Text
}

func (h *cursorEventHandler) HandleEvent(ev tcell.Event) bool {
	switch ev := ev.(type) {
	case *editor.CursorEvent:
		h.text.SetText(formatStatus(ev.Widget().(*editor.Editor)))
		return true
	}
	return false
}

func formatStatus(e *editor.Editor) string {
	x, y := e.GetCursor()
	return fmt.Sprintf("%d,%d", y+1, x+1)
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
	root.BoxLayout.SetOrientation(views.Vertical)

	root.editor = editor.New()
	root.editor.SetContent(buf)
	root.editor.SetStyle(tcell.StyleDefault.
		Foreground(tcell.ColorBlack).
		Background(tcell.ColorWhite).Underline(true))
	root.BoxLayout.AddWidget(root.editor, 1.0)

	root.status = views.NewText()
	root.status.SetStyle(tcell.StyleDefault.
		Foreground(tcell.ColorWhite).
		Background(tcell.ColorBlack))
	root.status.SetText(formatStatus(root.editor))
	root.BoxLayout.AddWidget(root.status, 0)

	root.editor.Watch(&cursorEventHandler{text: root.status})

	app.SetRootWidget(root)
	if err := app.Run(); err != nil {
		return err
	}
	return nil
}
