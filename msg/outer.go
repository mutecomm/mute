// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"encoding/binary"
	"io"

	"github.com/mutecomm/mute/log"
)

type outerHeader struct {
	//  1:	Pre-Header. Version, Cyphersuit, Header-Keys
	//  2:	Encrypted Header.
	//  4:	Crypto setup. Nonce/IV
	//  8:	HMAC. Result of HMAC calculation.
	// 16:	Symmetric encrypted packet.
	Type        uint8
	PLen        uint16 // Length of packet NOT including header
	PacketCount uint32 // Number of packet counted from first packet (count 0).
	inner       []byte
}

// outer header types
const (
	preHeaderPacket = 1
	encryptedHeader = 2
	cryptoSetup     = 4
	hmacPacket      = 8
	encryptedPacket = 16
)

// outer header sizes
const (
	preHeaderSize       = 73
	encryptedHeaderSize = 7201
	cryptoSetupSize     = 23
	encryptedPacketSize = 12 // without any content
	signatureSize       = 76 // encrypted packet containing a single signature
	hmacSize            = 71
)

func newOuterHeader(ohType uint8, count uint32, inner []byte) *outerHeader {
	var oh outerHeader
	oh.Type = ohType
	oh.PLen = uint16(len(inner))
	oh.PacketCount = count
	oh.inner = inner
	return &oh
}

func (oh *outerHeader) size() uint16 {
	return 1 + 2 + 4 + oh.PLen
}

func (oh *outerHeader) write(w io.Writer, withInner bool) error {
	if err := binary.Write(w, binary.BigEndian, oh.Type); err != nil {
		return log.Error(err)
	}
	if err := binary.Write(w, binary.BigEndian, oh.PLen); err != nil {
		return log.Error(err)
	}
	if err := binary.Write(w, binary.BigEndian, oh.PacketCount); err != nil {
		return log.Error(err)
	}
	if withInner {
		if _, err := w.Write(oh.inner); err != nil {
			return log.Error(err)
		}
	}
	return nil
}

func readOuterHeader(r io.Reader) (*outerHeader, error) {
	var oh outerHeader
	// read Type
	if err := binary.Read(r, binary.BigEndian, &oh.Type); err != nil {
		return nil, log.Error(err)
	}
	if oh.Type != 0 && // allow undefined type, catch this error later
		oh.Type != preHeaderPacket &&
		oh.Type != encryptedHeader &&
		oh.Type != cryptoSetup &&
		oh.Type != hmacPacket &&
		oh.Type != encryptedPacket {
		return nil, log.Errorf("msg: invalid outer header type %d", oh.Type)
	}
	// read Plen
	if err := binary.Read(r, binary.BigEndian, &oh.PLen); err != nil {
		return nil, log.Error(err)
	}
	// read PacketCount
	if err := binary.Read(r, binary.BigEndian, &oh.PacketCount); err != nil {
		return nil, log.Error(err)
	}
	// read inner packet
	oh.inner = make([]byte, oh.PLen)
	if _, err := io.ReadFull(r, oh.inner); err != nil {
		return nil, log.Error(err)
	}
	return &oh, nil
}
