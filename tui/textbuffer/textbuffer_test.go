// Copyright (c) 2017 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package textbuffer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmpty(t *testing.T) {
	tb := New(nil)
	assert.Equal(t, 0, tb.LineLenRune(0))
	assert.Equal(t, 0, tb.LineLenChar(0))
	assert.Equal(t, 0, tb.LineLenCell(0))
}

func TestHelloWorld(t *testing.T) {
	s := "Hello, 世界"
	tb := New([]byte(s))
	assert.Equal(t, 9, tb.LineLenRune(0))
	assert.Equal(t, 9, tb.LineLenChar(0))
	assert.Equal(t, 11, tb.LineLenCell(0))
	assert.Equal(t, 'H', tb.GetChar(0, 0)[0])
	assert.Equal(t, '世', tb.GetChar(7, 0)[0])
	assert.Equal(t, '界', tb.GetChar(8, 0)[0])
	c, w := tb.GetCell(0, 0)
	assert.Equal(t, 'H', c[0])
	assert.Equal(t, 1, w)
	c, w = tb.GetCell(7, 0)
	assert.Equal(t, '世', c[0])
	assert.Equal(t, 2, w)
	c, w = tb.GetCell(8, 0)
	assert.Equal(t, '世', c[0])
	assert.Equal(t, 0, w)
	var b bytes.Buffer
	err := tb.Write(&b)
	if assert.NoError(t, err) {
		assert.Equal(t, s, b.String())
	}
}
