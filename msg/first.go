// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

// IMPORTANT: You need a very good reason to change this file, because changes
// might break compatibility between different message formats!

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/mutecomm/mute/log"
)

// ReadFirstOuterHeader reads the first outer header from the base64 decoder r
// and returns the version and the preHeader for further processing. This
// function is intended to be used outside the msg package to allow to check
// for incompatible message format changes down the line.
func ReadFirstOuterHeader(r io.Reader) (version uint16, preHeader []byte, err error) {
	var (
		Type        uint8
		PLen        uint16
		PacketCount uint32
	)
	// read Type
	if err := binary.Read(r, binary.BigEndian, &Type); err != nil {
		return 0, nil, err
	}
	if Type != 1 {
		return 0, nil, log.Error(ErrNotPreHeader)
	}
	// read Plen
	if err := binary.Read(r, binary.BigEndian, &PLen); err != nil {
		return 0, nil, log.Error(err)
	}
	// read PacketCount
	if err := binary.Read(r, binary.BigEndian, &PacketCount); err != nil {
		return 0, nil, log.Error(err)
	}
	if PacketCount != 0 {
		return 0, nil, log.Error(ErrWrongCount)
	}
	// read inner packet
	preHeader = make([]byte, PLen)
	if _, err := io.ReadFull(r, preHeader); err != nil {
		return 0, nil, log.Error(err)
	}
	// parse version
	if err := binary.Read(bytes.NewBuffer(preHeader), binary.BigEndian, &version); err != nil {
		return 0, nil, log.Error(err)
	}
	return
}
