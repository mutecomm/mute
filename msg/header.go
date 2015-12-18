// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/padding"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/uid/length"
	"github.com/mutecomm/mute/util/digits"
	"golang.org/x/crypto/nacl/box"
)

// lengthEncryptedHeader defines the length of an encrypted header.
// This must always be the same in all messages! 5852 + 1316 = 7168.
const lengthEncryptedHeader = 7168

// Some wiggle room which can be taken out of padding if the need arises.
const wiggleRoom = 1316

// Header status codes.
const (
	statusOK    = 0
	statusReset = 1
	statusError = 2
)

type header struct {
	Ciphersuite                 string        // ciphersuite to use (header encryption is always NaCL)
	RecipientPubHash            string        // SHA512(RecipientIdentityPub)
	RecipientTempHash           string        // SHA512(RecipientKeyInitPub) || SHA512(RecipientSessionPub)
	SenderIdentity              string        // identity of sender
	SenderSessionPub            uid.KeyEntry  // public key of sender session
	SenderIdentityPubHash       string        // SHA512(SenderIdentityPub)
	SenderIdentityPub           uid.KeyEntry  // duplicate from SenderUID for easy parsing
	NextSenderSessionPub        *uid.KeyEntry // optional
	NextRecipientSessionPubSeen *uid.KeyEntry // only if seen
	NymAddress                  string        // address to receive future messages at
	MaxDelay                    uint64        // TODO
	SenderSessionCount          uint64        // total number of messages sent in sessions before this SenderSessionPub was used
	SenderMessageCount          uint64        // total number of messages sent with this SenderSessionPub
	SenderUID                   string        // complete UID message in JSON
	SenderLastKeychainHash      string        // last entry known to sender from keyserver hashchain
	Status                      uint8         // always a single digit in JSON!
	Padding                     string        // header padding
}

type headerPacket struct {
	Nonce                 [24]byte // for NaCL
	LengthEncryptedHeader uint16   // the length of the encrypted header
	EncryptedHeader       []byte   // the actual encrypted header
}

func newHeader(
	sender, recipient *uid.Message,
	recipientTempHash string,
	senderSessionPub, nextSenderSessionPub,
	nextRecipientSessionPubSeen *uid.KeyEntry,
	senderSessionCount, senderMessageCount uint64,
	senderLastKeychainHash string,
	rand io.Reader,
) (*header, error) {
	if len(senderLastKeychainHash) != hashchain.EntryBase64Len {
		return nil, log.Errorf("msg: last hashchain entry '%s' does not have base64 length %d (but %d)",
			senderLastKeychainHash, hashchain.EntryBase64Len, len(senderLastKeychainHash))
	}
	h := &header{
		Ciphersuite:                 uid.DefaultCiphersuite, // at the moment we only support one ciphersuite
		RecipientPubHash:            recipient.PubHash(),
		RecipientTempHash:           recipientTempHash,
		SenderIdentity:              sender.Identity(),
		SenderSessionPub:            *senderSessionPub,
		SenderIdentityPubHash:       sender.PubHash(),
		SenderIdentityPub:           *sender.PubKey(),
		NextSenderSessionPub:        nextSenderSessionPub,
		NextRecipientSessionPubSeen: nextRecipientSessionPubSeen,
		NymAddress:                  sender.UIDContent.NYMADDRESS, // TODO: set the correct nymaddress!
		MaxDelay:                    0,                            // TODO
		SenderSessionCount:          senderSessionCount,
		SenderMessageCount:          senderMessageCount,
		SenderUID:                   string(sender.JSON()),
		SenderLastKeychainHash:      senderLastKeychainHash,
		Status:                      statusOK, // TODO
		Padding:                     "",       // is set below
	}

	// calculate padding length
	padLen := wiggleRoom
	// pad sender identity
	if len(h.SenderIdentity) > identity.MaxLen {
		return nil, log.Error("msg: sender identity is too long")
	}
	padLen += identity.MaxLen - len(h.SenderIdentity)
	// pad nextSenderSessionPub
	if nextSenderSessionPub == nil {
		padLen += length.KeyEntryECDHE25519 - length.Nil
	}
	// pad nextRecipientSessionPubSeen
	if nextRecipientSessionPubSeen == nil {
		padLen += length.KeyEntryECDHE25519 - length.Nil
	}
	// pad nym address
	if len(h.NymAddress) > length.MaxNymAddress {
		return nil, log.Error("msg: nym address is too long")
	}
	padLen += length.MaxNymAddress - len(h.NymAddress)
	// pad integers
	padLen += 20 - digits.Count(h.MaxDelay)
	padLen += 20 - digits.Count(h.SenderSessionCount)
	padLen += 20 - digits.Count(h.SenderMessageCount)
	// pad sender UIDMessage
	if len(h.SenderUID) > length.MaxUIDMessage {
		return nil, log.Error("msg: sender UIDMesssage is too long")
	}
	padLen += length.MaxUIDMessage - len(h.SenderUID)
	// generate padding
	randLen := padLen/2 + padLen%2
	pad, err := padding.Generate(randLen, cipher.RandReader)
	if err != nil {
		return nil, err
	}
	// set padding
	p := hex.EncodeToString(pad)
	if padLen%2 == 1 {
		p = p[:len(p)-1]
	}
	h.Padding = p
	return h, nil
}

func newHeaderPacket(h *header, recipientIdentityPub, senderHeaderPriv *[32]byte, rand io.Reader) (*headerPacket, error) {
	var hp headerPacket
	jsn, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, hp.Nonce[:]); err != nil {
		return nil, log.Error(err)
	}
	hp.EncryptedHeader = box.Seal(hp.EncryptedHeader, jsn, &hp.Nonce, recipientIdentityPub, senderHeaderPriv)
	hp.LengthEncryptedHeader = uint16(len(hp.EncryptedHeader))
	if hp.LengthEncryptedHeader != lengthEncryptedHeader {
		return nil, log.Errorf("msg: encrypted header has wrong length (%d != %d)",
			hp.LengthEncryptedHeader, lengthEncryptedHeader)
	}
	return &hp, nil
}

func (hp *headerPacket) write(w io.Writer) error {
	//log.Debugf("hp.Nonce: %s", base64.Encode(hp.Nonce[:]))
	if _, err := w.Write(hp.Nonce[:]); err != nil {
		return log.Error(err)
	}
	//log.Debugf("hp.LengthEncryptedHeader: %d", hp.LengthEncryptedHeader)
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
	//log.Debugf("hp.Nonce: %s", base64.Encode(hp.Nonce[:]))
	// read length of encrypted header
	if err := binary.Read(r, binary.BigEndian, &hp.LengthEncryptedHeader); err != nil {
		return 0, nil, nil, log.Error(err)
	}
	////log.Debugf("hp.LengthEncryptedHeader: %d", hp.LengthEncryptedHeader)
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
	// verify header
	if err := h.verify(); err != nil {
		return 0, nil, nil, err
	}
	return i, recipientID, &h, nil
}

// Verify KeyEntry messages in header.
func (h *header) verify() error {
	// check h.SenderSessionPub
	if err := h.SenderSessionPub.Verify(); err != nil {
		return err
	}
	if h.SenderSessionPub.FUNCTION != "ECDHE25519" {
		return log.Errorf("msg: wrong uid.SenderSessionPub.FUNCTION: %s",
			h.SenderSessionPub.FUNCTION)
	}
	// check h.SenderIdentityPub
	if err := h.SenderIdentityPub.Verify(); err != nil {
		return err
	}
	if h.SenderIdentityPub.FUNCTION != "ECDHE25519" {
		return log.Errorf("msg: wrong uid.SenderIdentityPub.FUNCTION: %s",
			h.SenderIdentityPub.FUNCTION)
	}
	// check h.NextSenderSessionPub
	if h.NextSenderSessionPub != nil {
		if err := h.NextSenderSessionPub.Verify(); err != nil {
			return err
		}
		if h.NextSenderSessionPub.FUNCTION != "ECDHE25519" {
			return log.Errorf("msg: wrong uid.NextSenderSessionPub.FUNCTION: %s",
				h.SenderSessionPub.FUNCTION)
		}
	}
	// check h.NextRecipientSessionPubSeen
	if h.NextRecipientSessionPubSeen != nil {
		if err := h.NextRecipientSessionPubSeen.Verify(); err != nil {
			return err
		}
		if h.NextRecipientSessionPubSeen.FUNCTION != "ECDHE25519" {
			return log.Errorf("msg: wrong uid.NextRecipientSessionPubSeen.FUNCTION: %s",
				h.NextRecipientSessionPubSeen.FUNCTION)
		}
	}
	return nil
}
