// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package editor implements an editor widget which can also be used as a pager.
package editor

import (
	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/views"
)

// Editor is an embeddable editor views.Widget.
type Editor struct {
	views.WidgetWatchers
}

// NewPager creates a pager views.Widget for the UTF-8 buffer b.
func NewPager(b []byte) *Editor {
	return nil
}

// Draw implements the Draw() method of an editor views.Widget.
func (e *Editor) Draw() {
}

// Resize implements the Resize() method of an enditor views.Widget.
func (e *Editor) Resize() {
}

// HandleEvent implements the HandleEvent() method of an editor views.Widget.
func (e *Editor) HandleEvent(ev tcell.Event) bool {
	return false
}

// SetView implements the SetView() method of an editor views.Widget.
func (e *Editor) SetView(view views.View) {
}

// Size implements the Size() method of an editor views.Widget.
func (e *Editor) Size() (int, int) {
	return 0, 0
}
