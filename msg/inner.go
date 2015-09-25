package msg

import (
	"encoding/binary"
	"io"

	"github.com/mutecomm/mute/log"
)

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

// inner header types
const (
	padding   = 1
	data      = 2
	sign      = 4
	signature = 8
)

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
	// TODO: check possible types and type combinations (see outer.go)

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
