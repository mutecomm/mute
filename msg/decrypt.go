// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"io"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"
)

func rootKeyAgreementRecipient(
	senderIdentity, recipientIdentity string,
	senderSession, senderID, recipientKI, recipientID *uid.KeyEntry,
	previousRootKeyHash []byte,
	storeSession StoreSession,
) ([]byte, error) {
	recipientIdentityPub := recipientID.PublicKey32()
	recipientIdentityPriv := recipientID.PrivateKey32()

	recipientKeyInitPub := recipientKI.PublicKey32()
	recipientKeyInitPriv := recipientKI.PrivateKey32()

	// TODO: can sender cause panic here?
	senderSessionPub := senderSession.PublicKey32()
	senderIdentityPub := senderID.PublicKey32()

	// TODO: add verification rules!

	// compute t1
	t1, err := cipher.ECDH(recipientKeyInitPriv, senderIdentityPub, recipientKeyInitPub)
	if err != nil {
		return nil, err
	}

	// compute t2
	t2, err := cipher.ECDH(recipientKeyInitPriv, senderSessionPub, recipientKeyInitPub)
	if err != nil {
		return nil, err
	}

	// compute t3
	t3, err := cipher.ECDH(recipientIdentityPriv, senderSessionPub, recipientIdentityPub)
	if err != nil {
		return nil, err
	}

	// derive root key
	rootKey, err := deriveRootKey(t1, t2, t3, previousRootKeyHash)
	if err != nil {
		return nil, err
	}

	// generate message keys
	messageKey, err := generateMessageKeys(senderIdentity, recipientIdentity,
		rootKey, senderSessionPub[:], recipientKeyInitPub[:], storeSession)
	if err != nil {
		return nil, err
	}

	return messageKey, err
}

// Decrypt reads data from r, tries to decrypt it, and writes the result to w.
// findKeyEntry is called to find a KeyEntry when the corresponding pubKeyHash
// has been deciphered. storeSession is called to store new session keys.
// If the message was signed and the signature could be verified successfully
// the base64 encoded signature is returned. If the message was signed and the
// signature could not be verfied an error is returned.
//
// TODO: document identities, recipientIdentities, and previousRootKeyHash.
func Decrypt(
	w io.Writer,
	identities []string,
	recipientIdentities []*uid.KeyEntry,
	previousRootKeyHash []byte,
	preHeader []byte,
	r io.Reader,
	findKeyEntry FindKeyEntry,
	storeSession StoreSession,
) (senderID, sig string, err error) {
	log.Debugf("msg.Decrypt()")

	// read pre-header
	ph, err := readPreHeader(bytes.NewBuffer(preHeader))
	if err != nil {
		return "", "", err
	}
	if ph.LengthSenderHeaderPub != 32 {
		return "", "", log.Errorf("msg: ph.LengthSenderHeaderPub != 32")
	}
	var senderHeaderPub [32]byte
	copy(senderHeaderPub[:], ph.SenderHeaderPub)

	// read header packet
	oh, err := readOuterHeader(r)
	if err != nil {
		return "", "", err
	}
	if oh.Type != encryptedHeader {
		return "", "", log.Error(ErrNotEncryptedHeader)
	}
	count := uint32(1)
	if oh.PacketCount != count {
		return "", "", log.Error(ErrWrongCount)
	}
	count++
	i, recipientID, h, err := readHeader(&senderHeaderPub, recipientIdentities,
		bytes.NewBuffer(oh.inner))
	if err != nil {
		return "", "", err
	}
	senderID = h.SenderIdentity

	// proc sender UID in parallel
	res := make(chan *procUIDResult, 1)
	go procUID(h.SenderUID, res)

	// root key agreement
	recipientKI, err := findKeyEntry(h.RecipientTempHash)
	if err != nil {
		return "", "", err
	}
	messageKey, err := rootKeyAgreementRecipient(h.SenderIdentity,
		identities[i], &h.SenderSessionPub, &h.SenderIdentityPub, recipientKI,
		recipientID, previousRootKeyHash, storeSession)
	if err != nil {
		return "", "", err
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := symmetricKeys(messageKey)
	if err != nil {
		return "", "", err
	}

	// read crypto setup packet
	oh, err = readOuterHeader(r)
	if err != nil {
		return "", "", err
	}
	if oh.Type != cryptoSetup {
		return "", "", log.Error(ErrNotCryptoSetup)
	}
	if oh.PacketCount != count {
		return "", "", log.Error(ErrWrongCount)
	}
	count++
	if oh.PLen != aes.BlockSize {
		return "", "", log.Error(ErrWrongCryptoSetup)
	}
	iv := oh.inner

	// start HMAC calculation
	mac := hmac.New(sha512.New, hmacKey)
	if err := oh.write(mac, true); err != nil {
		return "", "", err
	}

	// actual decryption
	oh, err = readOuterHeader(r)
	if err != nil {
		return "", "", err
	}
	if oh.Type != encryptedPacket {
		return "", "", log.Error(ErrNotEncryptedPacket)
	}
	if oh.PacketCount != count {
		return "", "", log.Error(ErrWrongCount)
	}
	count++
	ciphertext := oh.inner
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.AES256CTRStream(cryptoKey, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	ih, err := readInnerHeader(bytes.NewBuffer(plaintext))
	if err != nil {
		return "", "", err
	}
	if ih.Type&dataType == 0 {
		return "", "", log.Error(ErrNotData)
	}
	var contentHash []byte
	if ih.Type&signType != 0 {
		// create signature hash
		contentHash = cipher.SHA512(ih.content)
	}
	if _, err := w.Write(ih.content); err != nil {
		return "", "", log.Error(err)
	}

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return "", "", err
	}

	// verify signature
	var sigBuf [ed25519.SignatureSize]byte
	if contentHash != nil {
		oh, err = readOuterHeader(r)
		if err != nil {
			return "", "", err
		}
		if oh.Type != encryptedPacket {
			return "", "", log.Error(ErrNotEncryptedPacket)
		}
		if oh.PacketCount != count {
			return "", "", log.Error(ErrWrongCount)
		}
		count++

		// continue HMAC calculation
		if err := oh.write(mac, true); err != nil {
			return "", "", err
		}

		ciphertext = oh.inner
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
		ih, err = readInnerHeader(bytes.NewBuffer(plaintext))
		if err != nil {
			return "", "", err
		}
		if ih.Type&signatureType == 0 {
			return "", "", log.Error(ErrNotSignaturePacket)
		}

		if len(ih.content) != ed25519.SignatureSize {
			return "", "", log.Error(ErrWrongSignatureLength)
		}

		copy(sigBuf[:], ih.content)
	} else {
		oh, err = readOuterHeader(r)
		if err != nil {
			return "", "", err
		}
		if oh.Type != encryptedPacket {
			return "", "", log.Error(ErrNotEncryptedPacket)
		}
		if oh.PacketCount != count {
			return "", "", log.Error(ErrWrongCount)
		}
		count++

		// continue HMAC calculation
		if err := oh.write(mac, true); err != nil {
			return "", "", err
		}

		ciphertext = oh.inner
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
		ih, err = readInnerHeader(bytes.NewBuffer(plaintext))
		if err != nil {
			return "", "", err
		}
		if ih.Type&paddingType == 0 {
			return "", "", log.Error(ErrNotPaddingPacket)
		}
	}
	// get processed sender UID
	uidRes := <-res
	if uidRes.err != nil {
		return "", "", uidRes.err
	}
	if contentHash != nil {
		if !ed25519.Verify(uidRes.msg.PublicSigKey32(), contentHash, &sigBuf) {
			return "", "", log.Error(ErrInvalidSignature)
		}
		// encode signature to base64 as return value
		sig = base64.Encode(sigBuf[:])
	}

	// read HMAC packet
	oh, err = readOuterHeader(r)
	if err != nil {
		return "", "", err
	}
	if oh.Type != hmacPacket {
		return "", "", log.Error(ErrNotHMACPacket)
	}
	if oh.PacketCount != count {
		return "", "", log.Error(ErrWrongCount)
	}
	count++
	if err := oh.write(mac, false); err != nil {
		return "", "", err
	}
	sum := mac.Sum(nil)
	log.Debugf("HMAC:       %s", base64.Encode(sum))

	if !hmac.Equal(sum, oh.inner) {
		return "", "", log.Error(ErrHMACsDiffer)
	}

	return
}
