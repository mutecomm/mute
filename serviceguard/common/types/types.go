// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package types implements types shared between client and server(s).
package types

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"
	"github.com/ronperry/cryptoedge/jjm"
)

var (
	// ErrSignerNeeded signals that a packet verification failed because no
	// public key was present but the packet was signed.
	ErrSignerNeeded = errors.New("types: signer needed for verification")
	// ErrBadSignature signals that a packet signature did not verify.
	ErrBadSignature = errors.New("types: bad signature")
	// ErrWrongSigner signals that the signer to be verified is not the signer
	// of the packet.
	ErrWrongSigner = errors.New("types: wrong signer")
)

const (
	// CallTypeReissue identifies a Reissue call.
	CallTypeReissue = iota
	// CallTypeSpend identifies a Spend call.
	CallTypeSpend
)

// Params contains the public parameters, encrypted private parameters, and
// PublicKey.
type Params struct {
	PublicKey     []byte
	PublicParams  jjm.BlindingParamClient
	PrivateParams []byte
	CanReissue    bool
}

// Backend describes a backend. Type is filename/dburl, Value is the content
// itself.
type Backend struct {
	Type  string
	Value interface{}
}

// Marshal a parameter set.
func (p Params) Marshal() ([]byte, error) {
	return asn1.Marshal(p)
}

// UnmarshalParams converts the output of GetParams into usable types.
func UnmarshalParams(d []byte) (pubKey *signkeys.PublicKey, pubParams *jjm.BlindingParamClient, privateParams []byte, canReissue bool, err error) {
	p := new(Params)
	_, err = asn1.Unmarshal(d, p)
	if err != nil {
		return nil, nil, nil, false, err
	}
	pubkey, err := new(signkeys.PublicKey).Unmarshal(p.PublicKey)
	if err != nil {
		return nil, nil, nil, false, err
	}
	return pubkey, &p.PublicParams, p.PrivateParams, p.CanReissue, nil
}

// ReissuePacket is a packet sent to the service guard to reissue a token.
type ReissuePacket struct {
	CallType   int32
	Token      []byte // The old token
	BlindToken []byte // The new token (blind)
	Params     []byte // The server-supplied blinding parameters
	Signature  []byte // Signature by owner of Token (or 0x00 if no owner)
}

// Marshal the packet into a byte slice.
func (p ReissuePacket) Marshal() ([]byte, error) {
	return asn1.Marshal(p)
}

// Unmarshal a byte slice into a packet.
func (p *ReissuePacket) Unmarshal(d []byte) (*ReissuePacket, error) {
	if p == nil {
		p = new(ReissuePacket)
	}
	_, err := asn1.Unmarshal(d, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Hash returns the hash of the packet excluding Signature.
func (p ReissuePacket) Hash() [sha256.Size]byte {
	return sha256.Sum256(p.Image())
}

// Image returns the signature image for a packet. The image are the hashes of
// the entries, appened. This allows proof from journal without recording too
// much data.
func (p ReissuePacket) Image() []byte {
	calltype := make([]byte, 8)
	binary.BigEndian.PutUint32(calltype, uint32(p.CallType))
	image := make([]byte, 0, sha256.Size*3)
	h := sha256.Sum256(append(calltype, p.Token...))
	image = append(image, h[:]...)
	h = sha256.Sum256(p.BlindToken)
	image = append(image, h[:]...)
	h = sha256.Sum256(p.Params)
	image = append(image, h[:]...)
	return image
}

// Sign a ReissuePacket.
func (p *ReissuePacket) Sign(privkey *[ed25519.PrivateKeySize]byte) {
	if privkey == nil {
		p.Signature = []byte{0x00}
		return
	}
	sig := ed25519.Sign(privkey, p.Image())
	p.Signature = make([]byte, len(sig))
	copy(p.Signature, sig[:])
	return
}

// Verify a packet signature using pubkey.
func (p ReissuePacket) Verify(pubkey *[ed25519.PublicKeySize]byte) error {
	var sig [ed25519.SignatureSize]byte
	if len(p.Signature) != 1 && pubkey == nil { // Packet is signed but no public key is givem
		return ErrSignerNeeded
	}
	if len(p.Signature) == 1 && pubkey == nil { // Packet is not signed
		return nil
	}
	copy(sig[:], p.Signature)
	ok := ed25519.Verify(pubkey, p.Image(), &sig)
	if ok {
		return nil
	}
	return ErrBadSignature
}

// ReissuePacketPrivate contains the private elements of a reissue request.
type ReissuePacketPrivate struct {
	PublicKey   []byte // The public key of the issuer as contained in params.
	Factors     []byte // The blinding factors. Needed for unblinding after signature.
	Token       []byte // The token. Needed for reconstruction after signature.
	RequestHash []byte // The hash of the ReissuePacket (as returned by p.Hash()). Used in caching.
	Request     []byte // The content of the request. Used in caching.
	CanReissue  bool   // Will a further reissue be possible?
}

// Marshal struct into []byte.
func (r ReissuePacketPrivate) Marshal() ([]byte, error) {
	return asn1.Marshal(r)
}

// Unmarshal []byte into ReissuePacketPrivate.
func (r *ReissuePacketPrivate) Unmarshal(d []byte) (*ReissuePacketPrivate, error) {
	if r == nil {
		r = new(ReissuePacketPrivate)
	}
	_, err := asn1.Unmarshal(d, r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SpendPacket is a packet for issuing a spend call.
type SpendPacket struct {
	CallType  int32
	Token     []byte // The old token
	Signature []byte // Signature by owner of Token (or 0x00 if no owner)
}

// Image returns the image of the SpendPacket for signing.
func (s *SpendPacket) Image() []byte {
	calltype := make([]byte, 8)
	binary.BigEndian.PutUint32(calltype, uint32(s.CallType))
	h := sha256.Sum256(append(calltype, s.Token...))
	return h[:]
}

// Sign a SpendPacket.
func (s *SpendPacket) Sign(privkey *[ed25519.PrivateKeySize]byte) {
	if privkey == nil {
		s.Signature = []byte{0x00}
		return
	}
	sig := ed25519.Sign(privkey, s.Image())
	s.Signature = make([]byte, len(sig))
	copy(s.Signature, sig[:])
	return
}

// Verify a SpendPacket.
func (s *SpendPacket) Verify(pubkey *[ed25519.PublicKeySize]byte) error {
	var sig [ed25519.SignatureSize]byte
	if len(s.Signature) != 1 && pubkey == nil { // Packet is signed but no public key is givem
		return ErrSignerNeeded
	}
	if len(s.Signature) == 1 && pubkey == nil { // Packet is not signed
		return nil
	}
	copy(sig[:], s.Signature)
	ok := ed25519.Verify(pubkey, s.Image(), &sig)
	if ok {
		return nil
	}
	return ErrBadSignature
}

// Marshal struct into []byte.
func (s SpendPacket) Marshal() ([]byte, error) {
	return asn1.Marshal(s)
}

// Unmarshal []byte into SpendPacket.
func (s *SpendPacket) Unmarshal(d []byte) (*SpendPacket, error) {
	if s == nil {
		s = new(SpendPacket)
	}
	_, err := asn1.Unmarshal(d, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
