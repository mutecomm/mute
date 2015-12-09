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
	keyStore KeyStore,
) (*SessionState, error) {
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
	ss, err := generateMessageKeys(senderIdentity, recipientIdentity,
		rootKey, senderSessionPub[:], recipientKeyInitPub[:], keyStore)
	if err != nil {
		return nil, err
	}

	return ss, err
}

// DecryptArgs contains all arguments for a message decryption.
type DecryptArgs struct {
	Writer              io.Writer       // decrypted message is written here
	Identities          []string        // list of recipient identity strings
	RecipientIdentities []*uid.KeyEntry // list of recipient identity KeyEntries
	PreviousRootKeyHash []byte          // for root key agreement
	PreHeader           []byte          // preHeader read with ReadFirstOuterHeader()
	Reader              io.Reader       // data to decrypt is read here (not base64 encoded)
	KeyStore            KeyStore        // for managing session keys
}

// Decrypt decrypts a message with the argument given in args.
// The senderID is returned.
// If the message was signed and the signature could be verified successfully
// the base64 encoded signature is returned. If the message was signed and the
// signature could not be verfied an error is returned.
func Decrypt(args *DecryptArgs) (senderID, sig string, err error) {
	log.Debugf("msg.Decrypt()")

	// read pre-header
	ph, err := readPreHeader(bytes.NewBuffer(args.PreHeader))
	if err != nil {
		return "", "", err
	}
	if ph.LengthSenderHeaderPub != 32 {
		return "", "", log.Errorf("msg: ph.LengthSenderHeaderPub != 32")
	}
	var senderHeaderPub [32]byte
	copy(senderHeaderPub[:], ph.SenderHeaderPub)

	// read header packet
	oh, err := readOuterHeader(args.Reader)
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
	i, recipientID, h, err := readHeader(&senderHeaderPub,
		args.RecipientIdentities, bytes.NewBuffer(oh.inner))
	if err != nil {
		return "", "", err
	}
	senderID = h.SenderIdentity

	// proc sender UID in parallel
	res := make(chan *procUIDResult, 1)
	go procUID(h.SenderUID, res)

	// get session state
	var messageKey [64]byte // TODO
	ss, err := args.KeyStore.GetSessionState(h.SenderIdentity, args.Identities[i])
	if err != nil {
		return "", "", err
	}
	if ss == nil {
		// no session found -> start first session
		// root key agreement
		recipientKI, err := args.KeyStore.FindKeyEntry(h.RecipientTempHash)
		if err != nil {
			return "", "", err
		}
		ss, err = rootKeyAgreementRecipient(h.SenderIdentity,
			args.Identities[i], &h.SenderSessionPub, &h.SenderIdentityPub,
			recipientKI, recipientID, args.PreviousRootKeyHash, args.KeyStore)
		if err != nil {
			return "", "", err
		}
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := deriveSymmetricKeys(&messageKey)
	if err != nil {
		return "", "", err
	}

	// read crypto setup packet
	oh, err = readOuterHeader(args.Reader)
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
	oh, err = readOuterHeader(args.Reader)
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
	if _, err := args.Writer.Write(ih.content); err != nil {
		return "", "", log.Error(err)
	}

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return "", "", err
	}

	// verify signature
	var sigBuf [ed25519.SignatureSize]byte
	if contentHash != nil {
		oh, err = readOuterHeader(args.Reader)
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
		oh, err = readOuterHeader(args.Reader)
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
	oh, err = readOuterHeader(args.Reader)
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
