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
	"io/ioutil"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/padding"
	"github.com/mutecomm/mute/uid"
)

func rootKeyAgreementSender(
	senderID, recipientID *uid.Message,
	senderSession, recipientKI *uid.KeyEntry,
	previousRootKeyHash []byte,
	keyStore KeyStore,
) error {
	senderIdentityPub := senderID.PublicEncKey32()
	senderIdentityPriv := senderID.PrivateEncKey32()
	senderSessionPub := senderSession.PublicKey32()
	senderSessionPriv := senderSession.PrivateKey32()
	recipientIdentityPub := recipientID.PublicEncKey32()
	recipientKeyInitPub := recipientKI.PublicKey32()

	// compute t1
	t1, err := cipher.ECDH(senderIdentityPriv, recipientKeyInitPub, senderIdentityPub)
	if err != nil {
		return err
	}

	// compute t2
	t2, err := cipher.ECDH(senderSessionPriv, recipientKeyInitPub, senderSessionPub)
	if err != nil {
		return err
	}

	// compute t3
	t3, err := cipher.ECDH(senderSessionPriv, recipientIdentityPub, senderSessionPub)
	if err != nil {
		return err
	}

	// derive root key
	rootKey, err := deriveRootKey(t1, t2, t3, previousRootKeyHash)
	if err != nil {
		return err
	}

	// generate message keys
	err = generateMessageKeys(senderID.Identity(),
		recipientID.Identity(), rootKey, false, senderSessionPub[:],
		recipientKeyInitPub[:], keyStore)
	if err != nil {
		return err
	}
	return nil
}

// EncryptArgs contains all arguments for a message encryption.
type EncryptArgs struct {
	Writer                 io.Writer    // encrypted messagte is written here (base64 encoded)
	From                   *uid.Message // sender UID
	To                     *uid.Message // recipient UID
	SenderLastKeychainHash string       // last hash chain entry known to the sender
	PreviousRootKeyHash    []byte       // has to contain the previous root key hash, if it exists
	PrivateSigKey          *[64]byte    // if this is s not nil the message is signed with the key
	Reader                 io.Reader    // data to encrypt is read here
	Rand                   io.Reader    // random source
	KeyStore               KeyStore     // for managing session keys
}

// Encrypt encrypts a message with the argument given in args and returns the
// nymAddress the message should be delivered to.
func Encrypt(args *EncryptArgs) (nymAddress string, err error) {
	log.Debugf("msg.Encrypt()")

	// create sender key
	senderHeaderKey, err := cipher.Curve25519Generate(cipher.RandReader)
	if err != nil {
		return "", log.Error(err)
	}

	// create pre-header
	ph := newPreHeader(senderHeaderKey.PublicKey()[:])

	// create base64 encoder
	var out bytes.Buffer
	wc := base64.NewEncoder(&out)

	// write pre-header
	var buf bytes.Buffer
	var count uint32
	if err := ph.write(&buf); err != nil {
		return "", err
	}
	oh := newOuterHeader(preHeaderPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// get session state
	sender := args.From.Identity()
	recipient := args.To.Identity()
	ss, err := args.KeyStore.GetSessionState(sender, recipient)
	if err != nil {
		return "", err
	}
	if ss == nil {
		// no session found -> start first session
		// get
		var recipientTemp *uid.KeyEntry
		recipientTemp, nymAddress, err = args.KeyStore.GetPublicKeyEntry(args.To)
		if err != nil {
			return "", err
		}
		// create session key
		var senderSession uid.KeyEntry
		if err := senderSession.InitDHKey(args.Rand); err != nil {
			return "", err
		}
		// root key agreement
		err = rootKeyAgreementSender(args.From, args.To, &senderSession,
			recipientTemp, args.PreviousRootKeyHash, args.KeyStore)
		if err != nil {
			return "", err
		}
		// create next session key
		var nextSenderSession uid.KeyEntry
		if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
			return "", err
		}
		// set session state
		ss = &SessionState{
			SenderSessionCount:          0,
			SenderMessageCount:          0,
			RecipientSessionCount:       0,
			RecipientMessageCount:       0,
			RecipientTempHash:           recipientTemp.HASH,
			SenderSessionPub:            senderSession,
			NextSenderSessionPub:        &nextSenderSession,
			NextRecipientSessionPubSeen: nil,
		}
		err = args.KeyStore.SetSessionState(sender, recipient, ss)
		if err != nil {
			return "", err
		}
	}

	// create header
	h, err := newHeader(args.From, args.To, ss.RecipientTempHash,
		&ss.SenderSessionPub, ss.NextSenderSessionPub,
		ss.NextRecipientSessionPubSeen, ss.SenderSessionCount,
		ss.SenderMessageCount, args.SenderLastKeychainHash, args.Rand)
	if err != nil {
		return "", err
	}

	// create (encrypted) header packet
	recipientIdentityPub, err := args.To.PublicKey()
	if err != nil {
		return "", err
	}
	hp, err := newHeaderPacket(h, recipientIdentityPub, senderHeaderKey.PrivateKey(), args.Rand)
	if err != nil {
		return "", err
	}

	// write (encrypted) header packet
	buf.Reset()
	if err := hp.write(&buf); err != nil {
		return "", err
	}
	oh = newOuterHeader(encryptedHeader, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// get message key
	messageKey, err := args.KeyStore.GetMessageKey(sender, recipient, true,
		ss.SenderMessageCount)
	if err != nil {
		return "", err
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := deriveSymmetricKeys(messageKey)
	if err != nil {
		return "", err
	}

	// write crypto setup packet
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(args.Rand, iv); err != nil {
		return "", log.Error(err)
	}
	oh = newOuterHeader(cryptoSetup, count, iv)

	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// start HMAC calculation
	mac := hmac.New(sha512.New, hmacKey)
	if err := oh.write(mac, true); err != nil {
		return "", err
	}

	// actual encryption
	content, err := ioutil.ReadAll(args.Reader)
	if err != nil {
		return "", log.Error(err)
	}
	// enforce maximum content length
	if len(content) > MaxContentLength {
		return "", log.Errorf("len(content) = %d > %d = MaxContentLength)",
			len(content), MaxContentLength)
	}

	// encrypted packet
	var contentHash []byte
	var innerType uint8
	if args.PrivateSigKey != nil {
		contentHash = cipher.SHA512(content)
		innerType = dataType | signType
	} else {
		innerType = dataType
	}
	ih := newInnerHeader(innerType, false, content)
	buf.Reset()
	if err := ih.write(&buf); err != nil {
		return "", err
	}
	stream := cipher.AES256CTRStream(cryptoKey, iv)
	stream.XORKeyStream(buf.Bytes(), buf.Bytes())
	oh = newOuterHeader(encryptedPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return "", err
	}

	// signature header & padding
	buf.Reset()
	if args.PrivateSigKey != nil {
		sig := ed25519.Sign(args.PrivateSigKey, contentHash)
		// signature
		ih = newInnerHeader(signatureType, true, sig[:])
		if err := ih.write(&buf); err != nil {
			return "", err
		}
		// padding
		padLen := MaxContentLength - len(content)
		pad, err := padding.Generate(padLen, cipher.RandReader)
		if err != nil {
			return "", err
		}
		ih = newInnerHeader(paddingType, false, pad)
		if err := ih.write(&buf); err != nil {
			return "", err
		}
	} else {
		// just padding
		padLen := MaxContentLength + signatureSize - encryptedPacketSize +
			innerHeaderSize - len(content)
		pad, err := padding.Generate(padLen, cipher.RandReader)
		if err != nil {
			return "", err
		}
		ih = newInnerHeader(paddingType, false, pad)
		if err := ih.write(&buf); err != nil {
			return "", err
		}
	}
	// encrypt inner header
	stream.XORKeyStream(buf.Bytes(), buf.Bytes())
	oh = newOuterHeader(encryptedPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return "", err
	}

	// create HMAC header
	oh = newOuterHeader(hmacPacket, count, nil)
	oh.PLen = sha512.Size
	if err := oh.write(mac, false); err != nil {
		return "", err
	}
	oh.inner = mac.Sum(oh.inner)
	log.Debugf("HMAC:       %s", base64.Encode(oh.inner))
	if err := oh.write(wc, true); err != nil {
		return "", err
	}
	count++

	// write output
	wc.Close()
	if out.Len() != EncodedMsgSize {
		return "", log.Errorf("out.Len() = %d != %d = EncodedMsgSize)",
			out.Len(), EncodedMsgSize)
	}
	if _, err := io.Copy(args.Writer, &out); err != nil {
		return "", log.Error(err)
	}

	// delete message key
	err = args.KeyStore.DelMessageKey(sender, recipient, true,
		ss.SenderMessageCount)
	if err != nil {
		return "", err
	}
	// increase SenderMessageCount
	ss.SenderMessageCount++
	err = args.KeyStore.SetSessionState(sender, recipient, ss)
	if err != nil {
		return "", err
	}

	return
}
