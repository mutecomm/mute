// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package editor

import (
	"unicode/utf8"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/views"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/tui/textbuffer"
)

type textBufferModel struct {
	tb     *textbuffer.TextBuffer
	width  int  // text buffer
	height int  // text buffer
	x      int  // cursor
	y      int  // cursor
	cursor bool // cursor (enabled)
	hidden bool // cursor
	style  tcell.Style
	editor *Editor // backlink to editor (for posting events)
}

func (m *textBufferModel) GetCell(x, y int) (rune, tcell.Style, []rune, int) {
	if x < 0 || y < 0 || y >= m.tb.Lines() || x >= m.tb.LineLenCell(y) {
		return 0, m.style, nil, 1
	}
	c, w := m.tb.GetCell(x, y)
	if w == 0 {
		// do not return second half of wide characters
		return utf8.RuneError, m.style, nil, 0
	}
	return c[0], m.style, c[1:], w
}

func (m *textBufferModel) GetBounds() (int, int) {
	return m.width, m.height
}

func (m *textBufferModel) limitCursor() {
	log.Tracef("editor.limitCursor()")
	log.Tracef("m.x=%d, m.y=%d", m.x, m.y)
	if m.x > m.width-1 {
		m.x = m.width - 1
	}
	if m.y > m.height-1 {
		m.y = m.height - 1
	}
	if m.x < 0 {
		m.x = 0
	}
	if m.y < 0 {
		m.y = 0
	}
	log.Tracef("m.x=%d, m.y=%d", m.x, m.y)
}

// CursorEvent reports a changed cursor event.
type CursorEvent struct {
	widget views.Widget
	tcell.EventTime
}

// Widget returns the views.Widget for the CursorEvent.
func (cev *CursorEvent) Widget() views.Widget {
	return cev.widget
}

// SetWidget set the views.Widget for the CursorEvent.
func (cev *CursorEvent) SetWidget(widget views.Widget) {
	cev.widget = widget
}

func (m *textBufferModel) postCursorEvent() {
	ev := &CursorEvent{}
	ev.SetWidget(m.editor)
	ev.SetEventNow()
	m.editor.PostEvent(ev)
}

func (m *textBufferModel) SetCursor(x, y int) {
	log.Tracef("editor.SetCursor(x=%d, y=%d)", x, y)
	m.x = x
	m.y = y
	m.limitCursor()
	m.postCursorEvent()
}

func (m *textBufferModel) GetCursor() (int, int, bool, bool) {
	return m.x, m.y, m.cursor, !m.hidden
}

func (m *textBufferModel) MoveCursor(x, y int) {
	log.Trace("editor.MoveCursor()")
	m.x += x
	m.y += y
	m.limitCursor()
	m.postCursorEvent()
}
