// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package textbuffer implements a buffer for displaying and editing UTF-8 text.
//
// Lines are separated by newlines ('\n', the Unicode code point U+000A) and
// the newline character is not contained explicitly in the lines of a text
// buffer. This makes addressing lines trivial, we use the y-coordinate
// starting at 0 for addressing them.
//
// However, handling UTF-8 within lines is more complicated and we have to
// differentiate multiple coordinate systems to handle them properly:
//
//   - the rune coordinate system
//   - the character coordinate system
//   - the cell coordinate system
//
// On the lowest level UTF-8 text is just an ordinary stream of bytes
// (Go type: byte). A text buffer does not explicitly address bytes.
//
// One or multiple bytes encode one UTF-8 code point (Go type: rune).
// Package "unicode/utf8" is used to split bytes into runes.
// We address runes in the rune coordinate system starting at 0.
//
// One or multiple runes encode one character. The mapping between runes and
// characters is usually one-to-one. That is, one rune encodes one character.
// However, UTF-8 also allows combining characters, for example for
// diacritical marks. This leads to different possible UTF-8 encodings for
// some characters and for other characters a multiple rune encoding is the
// only possible one.
// With the help of package "github.com/mattn/go-runewidth" a stream of runes
// is split into characters.
// We address characters in the character coordinate system starting at 0.
//
// When displaying characters in a terminal they usually occupy one cell.
// However, wide characters occupy two cells (for example, East Asian full
// width characters).
// Package "github.com/mattn/go-runewidth" is used to determine the width of
// characters.
// We address cells in the cell coordinate system starting at 0.
//
// For more information on UTF-8 in Go see also https://blog.golang.org/strings
package textbuffer

import (
	"bytes"
	"io"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

// TextBuffer is a line-oriented text buffer for displaying and editing UTF-8
// text.
type TextBuffer struct {
	lines []line // a text buffer is basically just a slice of lines
}

// line represents a line in a text buffer.
type line struct {
	runes []rune // a slice of the actual runes, its index are rune coordinates
	chars []int  // runes[chars[x-1]:chars[x]], character coordinates
	cells []cell // cell coordinates
}

type cell struct {
	charIndex int // index into the chars array of corresponding line
	charWidth int // 1: narrow, 2: wide, first half, 0: wide, second half
}

func (tb *TextBuffer) parseRow(row []byte) *line {
	var l line
	for len(row) > 0 {
		r, size := utf8.DecodeRune(row)
		switch runewidth.RuneWidth(r) {
		case 0: // combining rune
			if len(l.runes) == 0 {
				// The line starts with a combining rune, we could return an
				// error here, but that would mean that such a file cannot be
				// opened. Therefore we take the lesser evil and introduce a
				// space character instead.
				l.runes = append(l.runes, ' ')
				l.chars = append(l.chars, 1)
				l.cells = append(l.cells, cell{charIndex: 0, charWidth: 1})
			}
			l.runes = append(l.runes, r)
			l.chars[len(l.chars)-1]++
			// nothing needs to be updated for line.cells
		case 1: // narrow rune
			l.runes = append(l.runes, r)
			l.chars = append(l.chars, len(l.runes))
			l.cells = append(l.cells, cell{charIndex: len(l.chars) - 1, charWidth: 1})
		case 2: // wide rune
			l.runes = append(l.runes, r)
			l.chars = append(l.chars, len(l.runes))
			l.cells = append(l.cells, cell{charIndex: len(l.chars) - 1, charWidth: 2})
			l.cells = append(l.cells, cell{charIndex: len(l.chars) - 1, charWidth: 0})
		default:
			// should not happen, would be changed in runewidth.RuneWidth
			panic("textbuffer: runewidth > 2 encountered")
		}
		row = row[size:]
	}
	return &l
}

// New converts the UTF-8 buffer b into a new TextBuffer.
func New(b []byte) *TextBuffer {
	var tb TextBuffer
	// split buffer into rows (with newline separator)
	rows := bytes.Split(b, []byte("\n"))
	// convert all rows into lines
	for y := 0; y < len(rows); y++ {
		// parse row
		line := tb.parseRow(rows[y])
		// save line
		tb.lines = append(tb.lines, *line)
	}
	return &tb
}

// GetRune returns the rune in line y at position x of the rune coordinate
// system.
func (tb *TextBuffer) GetRune(x, y int) rune {
	if y < tb.Lines() {
		if x < len(tb.lines[y].runes) {
			return tb.lines[y].runes[x]
		}
	}
	return utf8.RuneError
}

// GetChar returns the character in line y at position x of the character
// coordinate system.
func (tb *TextBuffer) GetChar(x, y int) []rune {
	if y < tb.Lines() {
		if x < len(tb.lines[y].chars) {
			var l int
			if x > 0 {
				l = tb.lines[y].chars[x-1]
			}
			h := tb.lines[y].chars[x]
			return tb.lines[y].runes[l:h]
		}
	}
	return nil
}

// GetCell returns the character c in line y at position x of the cell
// coordinate system. It also returns the width of the character:
// 1: narrow, 2: wide, first half, 0: wide, second half.
func (tb *TextBuffer) GetCell(x, y int) (c []rune, width int) {
	if y < tb.Lines() {
		if x < len(tb.lines[y].cells) {
			c := tb.lines[y].cells[x]
			return tb.GetChar(c.charIndex, y), c.charWidth
		}
	}
	return nil, 0
}

// Lines returns the number of lines.
func (tb *TextBuffer) Lines() int {
	return len(tb.lines)
}

// LineLenRune returns the length of line y in the rune coordinate system.
// Returns 0 if y is an invalid coordinate.
func (tb *TextBuffer) LineLenRune(y int) int {
	if y < tb.Lines() {
		return len(tb.lines[y].runes)
	}
	return 0
}

// LineLenChar returns the length of line y in the character coordinate system.
// Returns 0 if y is an invalid coordinate.
func (tb *TextBuffer) LineLenChar(y int) int {
	if y < tb.Lines() {
		return len(tb.lines[y].chars)
	}
	return 0
}

// LineLenCell returns the length of line y in the cell coordinate system.
// Returns 0 if y is an invalid coordinate.
func (tb *TextBuffer) LineLenCell(y int) int {
	if y < tb.Lines() {
		return len(tb.lines[y].cells)
	}
	return 0
}

// MaxLineLenCell returns the maximum line length in the cell coordinate system.
func (tb *TextBuffer) MaxLineLenCell() int {
	var max int
	// TODO: cache results?
	for y := 0; y < tb.Lines(); y++ {
		l := tb.LineLenCell(y)
		if l > max {
			max = l
		}
	}
	return max
}

// Write writes the content of tb to w (including newlines).
func (tb *TextBuffer) Write(w io.Writer) error {
	buf := make([]byte, utf8.UTFMax)
	for y := 0; y < tb.Lines(); y++ {
		if y > 0 {
			// reintroduce newline
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		for x := 0; x < len(tb.lines[y].runes); x++ {
			// convert rune to UTF-8 byte slice and write it
			n := utf8.EncodeRune(buf, tb.lines[y].runes[x])
			if _, err := w.Write(buf[:n]); err != nil {
				return err
			}
		}
	}
	return nil
}
