// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package editor implements an editor widget which can also be used as a pager.
package editor

import (
	"sync"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/views"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/tui/textbuffer"
)

// Editor is an editor widget.
type Editor struct {
	model *textBufferModel
	once  sync.Once
	views.CellView
}

// SetContent of Editor.
func (e *Editor) SetContent(b []byte) {
	log.Trace("editor.SetContent()")
	e.Init()
	e.model.tb = textbuffer.New(b)
	e.model.width = e.model.tb.MaxLineLenCell()
	e.model.height = e.model.tb.Lines()
}

// SetStyle of Editor.
func (e *Editor) SetStyle(style tcell.Style) {
	e.model.style = style
	e.CellView.SetStyle(style)
}

// EnableCursor enables a soft cursor in the Editor.
func (e *Editor) EnableCursor(on bool) {
	log.Trace("editor.EnableCursor()")
	log.Tracef("e.model.x=%d, e.model.y=%d", e.model.x, e.model.y)
	e.Init()
	e.model.cursor = on
}

// HideCursor hides or shows the cursor in the Editor.
// If on is true, the cursor is hidden.
// Note that a cursor is only shown if it is enabled.
func (e *Editor) HideCursor(on bool) {
	e.Init()
	e.model.hidden = on
}

// Init initializes the Editor.
func (e *Editor) Init() {
	e.once.Do(func() {
		m := &textBufferModel{tb: textbuffer.New(nil), width: 0}
		e.model = m
		e.CellView.Init()
		e.CellView.SetModel(m)
	})
}

// New creates a blank Editor.
func New() *Editor {
	var e Editor
	e.Init()
	return &e
}
