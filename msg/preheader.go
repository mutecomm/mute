// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"encoding/binary"
	"io"

	"github.com/mutecomm/mute/log"
)

type preHeader struct {
	Version               uint16 // (0x00 0x01)
	LengthCiphersuite     uint16 // (0x00 0x1c)
	Ciphersuite           string // must be for now: "CURVE25519 XSALSA20 POLY1305"
	LengthSenderHeaderPub uint16 // length of the public sender header
	SenderHeaderPub       []byte // the actual sender header
}

func newPreHeader(senderHeaderPub []byte) *preHeader {
	ph := &preHeader{
		Version:               Version,
		LengthCiphersuite:     uint16(len(DefaultCiphersuite)),
		Ciphersuite:           DefaultCiphersuite,
		LengthSenderHeaderPub: uint16(len(senderHeaderPub)),
		SenderHeaderPub:       senderHeaderPub,
	}
	return ph
}

func (ph *preHeader) write(w io.Writer) error {
	//log.Debugf("ph.Version: %d", ph.Version)
	if err := binary.Write(w, binary.BigEndian, ph.Version); err != nil {
		return log.Error(err)
	}
	//log.Debugf("ph.LengthCiphersuite: %d", ph.LengthCiphersuite)
	if err := binary.Write(w, binary.BigEndian, ph.LengthCiphersuite); err != nil {
		return log.Error(err)
	}
	//log.Debugf("ph.Ciphersuite: %s", ph.Ciphersuite)
	if _, err := io.WriteString(w, ph.Ciphersuite); err != nil {
		return log.Error(err)
	}
	//log.Debugf("ph.LengthSenderHeaderPub: %d", ph.LengthSenderHeaderPub)
	if err := binary.Write(w, binary.BigEndian, ph.LengthSenderHeaderPub); err != nil {
		return log.Error(err)
	}
	if _, err := w.Write(ph.SenderHeaderPub); err != nil {
		return log.Error(err)
	}
	//log.Debugf("ph.SenderHeaderPub: %s", base64.Encode(ph.SenderHeaderPub))
	return nil
}

func readPreHeader(r io.Reader) (*preHeader, error) {
	var ph preHeader
	// read version
	if err := binary.Read(r, binary.BigEndian, &ph.Version); err != nil {
		return nil, log.Error(err)
	}
	if ph.Version != Version {
		return nil, log.Errorf("msg: invalid message version %d", ph.Version)
	}
	//log.Debugf("ph.Version: %d", ph.Version)
	// read length of ciphersuite
	if err := binary.Read(r, binary.BigEndian, &ph.LengthCiphersuite); err != nil {
		return nil, log.Error(err)
	}
	if ph.LengthCiphersuite != uint16(len(DefaultCiphersuite)) {
		return nil, log.Errorf("msg: invalid ciphersuite length %d", ph.LengthCiphersuite)
	}
	//log.Debugf("ph.LengthCiphersuite: %d", ph.LengthCiphersuite)
	// read ciphersuite
	p := make([]byte, ph.LengthCiphersuite)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, log.Error(err)
	}
	ph.Ciphersuite = string(p)
	if ph.Ciphersuite != DefaultCiphersuite {
		return nil, log.Errorf("msg: invalid ciphersuite '%s'", ph.Ciphersuite)
	}
	//log.Debugf("ph.Ciphersuite: %s", ph.Ciphersuite)
	// read length sender header pub
	if err := binary.Read(r, binary.BigEndian, &ph.LengthSenderHeaderPub); err != nil {
		return nil, log.Error(err)
	}
	//log.Debugf("ph.LengthSenderHeaderPub: %d", ph.LengthSenderHeaderPub)
	ph.SenderHeaderPub = make([]byte, ph.LengthSenderHeaderPub)
	if _, err := io.ReadFull(r, ph.SenderHeaderPub); err != nil {
		return nil, log.Error(err)
	}
	//log.Debugf("ph.SenderHeaderPub: %s", base64.Encode(ph.SenderHeaderPub))
	return &ph, nil
}
