// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/padding"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/length"
	"golang.org/x/crypto/nacl/box"
)

type header struct {
	Ciphersuite                 string
	RecipientPubHash            string
	RecipientTempHash           string
	SenderSessionPub            uid.KeyEntry
	SenderIdentity              string // identity of sender
	SenderIdentityPubHash       string
	SenderIdentityPub           uid.KeyEntry
	NextSenderSessionPub        *uid.KeyEntry // optional
	NextRecipientSessionPubSeen *uid.KeyEntry // only if seen
	NymAddress                  string
	MaxDelay                    uint64
	SenderSessionCount          uint64
	SenderMessageCount          uint64
	SenderUID                   string // complete UID message in JSON
	SenderLastKeychainHash      string
	Status                      uint8
	Padding                     []byte // TODO: compute correct padding length for header
}

type headerPacket struct {
	Nonce                 [24]byte // for NaCL
	LengthEncryptedHeader uint16
	EncryptedHeader       []byte
}

func newHeader(
	sender, recipient *uid.Message,
	recipientTemp, senderSession, nextSenderSessionPub,
	nextRecipientSessionPubSeen *uid.KeyEntry,
	senderLastKeychainHash string,
	rand io.Reader,
) (*header, error) {
	h := &header{
		Ciphersuite:                 uid.DefaultCiphersuite, // at the moment we only support one ciphersuite
		RecipientPubHash:            recipient.PubHash(),
		RecipientTempHash:           recipientTemp.HASH,
		SenderIdentity:              sender.Identity(),
		SenderSessionPub:            *senderSession,
		SenderIdentityPubHash:       sender.PubHash(),
		SenderIdentityPub:           *sender.PubKey(),
		NextSenderSessionPub:        nextSenderSessionPub,
		NextRecipientSessionPubSeen: nextRecipientSessionPubSeen,
		NymAddress:                  sender.UIDContent.NYMADDRESS,
		MaxDelay:                    0, // TODO
		SenderSessionCount:          0, // TODO
		SenderMessageCount:          0, // TODO
		SenderUID:                   string(sender.JSON()),
		SenderLastKeychainHash:      senderLastKeychainHash,
		Status:                      0,   // TODO
		Padding:                     nil, // TODO
	}
	// TODO: implement padding correctly
	var padLen int
	if nextSenderSessionPub == nil {
		padLen += length.KeyEntryECDHE25519 - length.Nil
	}
	if nextRecipientSessionPubSeen == nil {
		padLen += length.KeyEntryECDHE25519 - length.Nil
	}
	pad, err := padding.Generate(padLen, cipher.RandReader)
	if err != nil {
		return nil, err
	}
	h.Padding = pad
	return h, nil
}

func newHeaderPacket(h *header, recipientIdentityPub, senderHeaderPriv *[32]byte, rand io.Reader) (*headerPacket, error) {
	var hp headerPacket
	jsn, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	// TODO: show encrypted header contents
	// jsn2, _ := json.MarshalIndent(h, "", "  ")
	// fmt.Fprintln(os.Stderr, string(jsn2))

	if _, err := io.ReadFull(rand, hp.Nonce[:]); err != nil {
		return nil, log.Error(err)
	}
	hp.EncryptedHeader = box.Seal(hp.EncryptedHeader, jsn, &hp.Nonce, recipientIdentityPub, senderHeaderPriv)
	hp.LengthEncryptedHeader = uint16(len(hp.EncryptedHeader))
	return &hp, nil
}

func (hp *headerPacket) write(w io.Writer) error {
	log.Debugf("hp.Nonce: %s", base64.Encode(hp.Nonce[:]))
	if _, err := w.Write(hp.Nonce[:]); err != nil {
		return log.Error(err)
	}
	log.Debugf("hp.LengthEncryptedHeader: %d", hp.LengthEncryptedHeader)
	if err := binary.Write(w, binary.BigEndian, hp.LengthEncryptedHeader); err != nil {
		return log.Error(err)
	}
	if _, err := w.Write(hp.EncryptedHeader); err != nil {
		return log.Error(err)
	}
	return nil
}

func readHeader(
	senderHeaderPub *[32]byte,
	recipientIdentities []*uid.KeyEntry,
	r io.Reader,
) (int, *uid.KeyEntry, *header, error) {
	var hp headerPacket
	// read nonce
	if _, err := io.ReadFull(r, hp.Nonce[:]); err != nil {
		return 0, nil, nil, log.Error(err)
	}
	log.Debugf("hp.Nonce: %s", base64.Encode(hp.Nonce[:]))
	// read length of encrypted header
	if err := binary.Read(r, binary.BigEndian, &hp.LengthEncryptedHeader); err != nil {
		return 0, nil, nil, log.Error(err)
	}
	log.Debugf("hp.LengthEncryptedHeader: %d", hp.LengthEncryptedHeader)
	// read encrypted header
	hp.EncryptedHeader = make([]byte, hp.LengthEncryptedHeader)
	if _, err := io.ReadFull(r, hp.EncryptedHeader); err != nil {
		return 0, nil, nil, log.Error(err)
	}
	// try to decrypt header
	var jsn []byte
	var suc bool
	var recipientID *uid.KeyEntry
	var i int
	for idx, ke := range recipientIdentities {
		jsn, suc = box.Open(jsn, hp.EncryptedHeader, &hp.Nonce, senderHeaderPub, ke.PrivateKey32())
		if suc {
			i = idx
			recipientID = ke
			break
		}
	}
	if !suc {
		return 0, nil, nil, log.Error("msg: could not find key to decrypt header")
	}
	var h header
	if err := json.Unmarshal(jsn, &h); err != nil {
		return 0, nil, nil, err
	}

	// TODO: show encrypted header contents
	// jsn2, _ := json.MarshalIndent(h, "", "  ")
	// fmt.Fprintln(os.Stderr, string(jsn2))

	return i, recipientID, &h, nil
}
