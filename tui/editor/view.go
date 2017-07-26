// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package editor

import (
	"sync"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/views"
)

type textBufferView struct {
	port     *views.ViewPort
	view     views.View
	content  views.Widget
	contentV *views.ViewPort
	cursorX  int
	cursorY  int
	style    tcell.Style
	lines    []string
	model    views.CellModel
	once     sync.Once

	views.WidgetWatchers
}

// Draw draws the content.
func (a *textBufferView) Draw() {

	port := a.port
	model := a.model
	port.Fill(' ', a.style)

	if a.view == nil {
		return
	}
	if model == nil {
		return
	}
	vw, vh := a.view.Size()
	for y := 0; y < vh; y++ {
		for x := 0; x < vw; x++ {
			a.view.SetContent(x, y, ' ', nil, a.style)
		}
	}

	ex, ey := model.GetBounds()
	vx, vy := port.Size()
	if ex < vx {
		ex = vx
	}
	if ey < vy {
		ey = vy
	}

	cx, cy, en, sh := a.model.GetCursor()
	for y := 0; y < ey; y++ {
		for x := 0; x < ex; x++ {
			ch, style, comb, wid := model.GetCell(x, y)
			if ch == 0 {
				ch = ' '
				style = a.style
			}
			if en && x == cx && y == cy && sh {
				style = style.Reverse(true)
			}
			port.SetContent(x, y, ch, comb, style)
			x += wid - 1
		}
	}
}

func (a *textBufferView) keyUp() {
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollUp(1)
		return
	}
	a.model.MoveCursor(0, -1)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyDown() {
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollDown(1)
		return
	}
	a.model.MoveCursor(0, 1)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyLeft() {
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollLeft(1)
		return
	}
	a.model.MoveCursor(-1, 0)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyRight() {
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollRight(1)
		return
	}
	a.model.MoveCursor(+1, 0)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyPgUp() {
	_, vy := a.port.Size()
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollUp(vy)
		return
	}
	a.model.MoveCursor(0, -vy)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyPgDn() {
	_, vy := a.port.Size()
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollDown(vy)
		return
	}
	a.model.MoveCursor(0, +vy)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyHome() {
	vx, vy := a.model.GetBounds()
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollUp(vy)
		a.port.ScrollLeft(vx)
		return
	}
	a.model.SetCursor(0, 0)
	a.MakeCursorVisible()
}

func (a *textBufferView) keyEnd() {
	vx, vy := a.model.GetBounds()
	if _, _, en, _ := a.model.GetCursor(); !en {
		a.port.ScrollDown(vy)
		a.port.ScrollRight(vx)
		return
	}
	a.model.SetCursor(vx, vy)
	a.MakeCursorVisible()
}

// MakeCursorVisible ensures that the cursor is visible, panning the ViewPort
// as necessary, if the cursor is enabled.
func (a *textBufferView) MakeCursorVisible() {
	if a.model == nil {
		return
	}
	x, y, enabled, _ := a.model.GetCursor()
	if enabled {
		a.MakeVisible(x, y)
	}
}

// HandleEvent handles events.  In particular, it handles certain key events
// to move the cursor or pan the view.
func (a *textBufferView) HandleEvent(e tcell.Event) bool {
	if a.model == nil {
		return false
	}
	switch e := e.(type) {
	case *tcell.EventKey:
		switch e.Key() {
		case tcell.KeyUp, tcell.KeyCtrlP:
			a.keyUp()
			return true
		case tcell.KeyDown, tcell.KeyCtrlN:
			a.keyDown()
			return true
		case tcell.KeyRight, tcell.KeyCtrlF:
			a.keyRight()
			return true
		case tcell.KeyLeft, tcell.KeyCtrlB:
			a.keyLeft()
			return true
		case tcell.KeyPgDn:
			a.keyPgDn()
			return true
		case tcell.KeyPgUp:
			a.keyPgUp()
			return true
		case tcell.KeyEnd:
			a.keyEnd()
			return true
		case tcell.KeyHome:
			a.keyHome()
			return true
		case tcell.KeyEnter:
			// TODO: add new line
		case tcell.KeyRune:
			// TODO: the following only apply to command mode!
			switch e.Rune() {
			case 'g':
				a.keyHome()
				return true
			case 'k':
				a.keyUp()
				return true
			case 'j':
				a.keyDown()
				return true
			case 'l':
				a.keyRight()
				return true
			case 'h':
				a.keyLeft()
				return true
			case ' ':
				a.keyPgDn()
				return true
			}
		}
	}
	return false
}

// Size returns the content size, based on the model.
func (a *textBufferView) Size() (int, int) {
	// We always return a minimum of two rows, and two columns.
	w, h := a.model.GetBounds()
	// Clip to a 2x2 minimum square; we can scroll within that.
	if w > 2 {
		w = 2
	}
	if h > 2 {
		h = 2
	}
	return w, h
}

// SetModel sets the model for this textBufferView.
func (a *textBufferView) SetModel(model views.CellModel) {
	w, h := model.GetBounds()
	model.SetCursor(0, 0)
	a.model = model
	a.port.SetContentSize(w, h, true)
	a.port.ValidateView()
	a.PostEventWidgetContent(a)
}

// SetView sets the View context.
func (a *textBufferView) SetView(view views.View) {
	port := a.port
	port.SetView(view)
	a.view = view
	if view == nil {
		return
	}
	width, height := view.Size()
	a.port.Resize(0, 0, width, height)
	if a.model != nil {
		w, h := a.model.GetBounds()
		a.port.SetContentSize(w, h, true)
	}
	a.Resize()
}

// Resize is called when the View is resized.  It will ensure that the
// cursor is visible, if present.
func (a *textBufferView) Resize() {
	// We might want to reflow text
	width, height := a.view.Size()
	a.port.Resize(0, 0, width, height)
	a.port.ValidateView()
	a.MakeCursorVisible()
}

// SetCursor sets the the cursor position.
func (a *textBufferView) SetCursor(x, y int) {
	a.cursorX = x
	a.cursorY = y
	a.model.SetCursor(x, y)
}

// SetCursorX sets the the cursor column.
func (a *textBufferView) SetCursorX(x int) {
	a.SetCursor(x, a.cursorY)
}

// SetCursorY sets the the cursor row.
func (a *textBufferView) SetCursorY(y int) {
	a.SetCursor(a.cursorX, y)
}

// MakeVisible makes the given coordinates visible, if they are not already.
// It does this by moving the ViewPort for the textBufferView.
func (a *textBufferView) MakeVisible(x, y int) {
	a.port.MakeVisible(x, y)
}

// SetStyle sets the the default fill style.
func (a *textBufferView) SetStyle(s tcell.Style) {
	a.style = s
}

// Init initializes a new textBufferView for use.
func (a *textBufferView) Init() {
	a.once.Do(func() {
		a.port = views.NewViewPort(nil, 0, 0, 0, 0)
		a.style = tcell.StyleDefault
	})
}
