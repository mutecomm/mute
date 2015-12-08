// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"encoding/binary"
	"io"

	"github.com/mutecomm/mute/log"
)

// inner header types
const (
	paddingType   = 1 // random padding data to fill packet
	dataType      = 2 // data
	signType      = 4 // packet will be included in signature
	signatureType = 8 // signature
)

// inner header size
const innerHeaderSize = 5 // without any content

type innerHeader struct {
	// 1: Padding (random padding data to fill packet)
	// 2: Data
	// 4: Sign (packet will be included in signature)
	// 8: Signature
	Type    uint8
	PLen    uint16 // Length of the packet NOT including header.
	More    uint8  // If set to 1, at least 1 more packet follows.
	Skip    uint8  // Skip N bytes following header... additional padding scheme. Zero in most cases.
	content []byte
}

func newInnerHeader(ihType uint8, more bool, content []byte) *innerHeader {
	var ih innerHeader
	ih.Type = ihType
	ih.PLen = uint16(len(content))
	if more {
		ih.More = 1
	}
	ih.content = content
	return &ih
}

func (ih *innerHeader) size() int {
	return 1 + 2 + 1 + 1 + len(ih.content)
}

func (ih *innerHeader) write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, ih.Type); err != nil {
		return log.Error(err)
	}
	if err := binary.Write(w, binary.BigEndian, ih.PLen); err != nil {
		return log.Error(err)
	}
	if err := binary.Write(w, binary.BigEndian, ih.More); err != nil {
		return log.Error(err)
	}
	if err := binary.Write(w, binary.BigEndian, ih.Skip); err != nil {
		return log.Error(err)
	}
	if _, err := w.Write(ih.content); err != nil {
		return log.Error(err)
	}
	return nil
}

func readInnerHeader(r io.Reader) (*innerHeader, error) {
	var ih innerHeader
	// read Type
	if err := binary.Read(r, binary.BigEndian, &ih.Type); err != nil {
		return nil, err
	}
	// check Type
	if ih.Type != paddingType &&
		ih.Type != dataType &&
		ih.Type != dataType|signType &&
		ih.Type != signatureType {
		return nil, log.Errorf("msg: invalid inner header type %d", ih.Type)
	}
	// read Plen
	if err := binary.Read(r, binary.BigEndian, &ih.PLen); err != nil {
		return nil, log.Error(err)
	}
	// read More
	if err := binary.Read(r, binary.BigEndian, &ih.More); err != nil {
		return nil, log.Error(err)
	}
	// read Skip
	if err := binary.Read(r, binary.BigEndian, &ih.Skip); err != nil {
		return nil, log.Error(err)
	}
	// read content
	ih.content = make([]byte, ih.PLen)
	if _, err := io.ReadFull(r, ih.content); err != nil {
		return nil, log.Error(err)
	}
	return &ih, nil
}
