// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package base64 implements base64 helper functions for Mute.
package base64

import (
	"encoding/base64"
	"io"
)

// base64Encoding defines the base64 encoding used in Mute.
var base64Encoding = base64.StdEncoding

// Decode returns the bytes represented by the base64 string s.
func Decode(s string) ([]byte, error) {
	return base64Encoding.DecodeString(s)
}

// Encode returns the base64 encoding of src.
func Encode(src []byte) string {
	return base64Encoding.EncodeToString(src)
}

// NewDecoder constructs a new base64 stream decoder.
func NewDecoder(r io.Reader) io.Reader {
	return base64.NewDecoder(base64Encoding, r)
}

// NewEncoder returns a new base64 stream encoder.
func NewEncoder(w io.Writer) io.WriteCloser {
	return base64.NewEncoder(base64Encoding, w)
}
