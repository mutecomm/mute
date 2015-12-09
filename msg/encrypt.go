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
) (*SessionState, error) {
	senderIdentityPub := senderID.PublicEncKey32()
	senderIdentityPriv := senderID.PrivateEncKey32()
	senderSessionPub := senderSession.PublicKey32()
	senderSessionPriv := senderSession.PrivateKey32()
	recipientIdentityPub := recipientID.PublicEncKey32()
	recipientKeyInitPub := recipientKI.PublicKey32()

	// compute t1
	t1, err := cipher.ECDH(senderIdentityPriv, recipientKeyInitPub, senderIdentityPub)
	if err != nil {
		return nil, err
	}

	// compute t2
	t2, err := cipher.ECDH(senderSessionPriv, recipientKeyInitPub, senderSessionPub)
	if err != nil {
		return nil, err
	}

	// compute t3
	t3, err := cipher.ECDH(senderSessionPriv, recipientIdentityPub, senderSessionPub)
	if err != nil {
		return nil, err
	}

	// derive root key
	rootKey, err := deriveRootKey(t1, t2, t3, previousRootKeyHash)
	if err != nil {
		return nil, err
	}

	// generate message keys
	ss, err := generateMessageKeys(senderID.Identity(),
		recipientID.Identity(), rootKey, false, senderSessionPub[:],
		recipientKeyInitPub[:], keyStore)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// EncryptArgs contains all arguments for a message encryption.
type EncryptArgs struct {
	Writer                      io.Writer     // encrypted messagte is written here (base64 encoded)
	From                        *uid.Message  // sender UID
	To                          *uid.Message  // recipient UID
	RecipientTemp               *uid.KeyEntry // RecipientKeyInitPub or RecipientSessionPub
	NextSenderSessionPub        *uid.KeyEntry // new SenderSessionPub to refresh the session
	NextRecipientSessionPubSeen *uid.KeyEntry // currently known NextSenderSessionPub of the other party
	SenderLastKeychainHash      string        // last hash chain entry known to the sender
	PreviousRootKeyHash         []byte        // has to contain the previous root key hash, if it exists
	PrivateSigKey               *[64]byte     // if it is s not nil the message is signed with the key
	Reader                      io.Reader     // data to encrypted is read here
	Rand                        io.Reader     // random source
	KeyStore                    KeyStore      // for managing session keys
}

// Encrypt encrypts a message with the argument given in args.
func Encrypt(args *EncryptArgs) error {
	log.Debugf("msg.Encrypt()")

	// create sender key
	senderHeaderKey, err := cipher.Curve25519Generate(cipher.RandReader)
	if err != nil {
		return nil
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
		return err
	}
	oh := newOuterHeader(preHeaderPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// create header
	var senderSession uid.KeyEntry
	if err := senderSession.InitDHKey(args.Rand); err != nil {
		return err
	}
	h, err := newHeader(args.From, args.To, args.RecipientTemp, &senderSession,
		args.NextSenderSessionPub, args.NextRecipientSessionPubSeen,
		args.SenderLastKeychainHash, args.Rand)
	if err != nil {
		return err
	}

	// create (encrypted) header packet
	recipientIdentityPub, err := args.To.PublicKey()
	if err != nil {
		return err
	}
	hp, err := newHeaderPacket(h, recipientIdentityPub, senderHeaderKey.PrivateKey(), args.Rand)
	if err != nil {
		return err
	}

	// write (encrypted) header packet
	buf.Reset()
	if err := hp.write(&buf); err != nil {
		return err
	}
	oh = newOuterHeader(encryptedHeader, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// get session state
	myID := args.From.Identity()
	contactID := args.To.Identity()
	ss, err := args.KeyStore.GetSessionState(myID, contactID)
	if err != nil {
		return err
	}
	if ss == nil {
		// no session found -> start first session
		// root key agreement
		ss, err = rootKeyAgreementSender(args.From, args.To, &senderSession,
			args.RecipientTemp, args.PreviousRootKeyHash, args.KeyStore)
		if err != nil {
			return err
		}
	}

	// get message key
	messageKey, err := args.KeyStore.GetMessageKey(myID, contactID, true,
		ss.SenderMessageCount)
	if err != nil {
		return err
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := deriveSymmetricKeys(messageKey)
	if err != nil {
		return err
	}

	// write crypto setup packet
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(args.Rand, iv); err != nil {
		return log.Error(err)
	}
	oh = newOuterHeader(cryptoSetup, count, iv)

	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// start HMAC calculation
	mac := hmac.New(sha512.New, hmacKey)
	if err := oh.write(mac, true); err != nil {
		return err
	}

	// actual encryption
	content, err := ioutil.ReadAll(args.Reader)
	if err != nil {
		return log.Error(err)
	}
	// enforce maximum content length
	if len(content) > MaxContentLength {
		return log.Errorf("len(content) = %d > %d = MaxContentLength)",
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
		return err
	}
	stream := cipher.AES256CTRStream(cryptoKey, iv)
	stream.XORKeyStream(buf.Bytes(), buf.Bytes())
	oh = newOuterHeader(encryptedPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return err
	}

	// signature header & padding
	buf.Reset()
	if args.PrivateSigKey != nil {
		sig := ed25519.Sign(args.PrivateSigKey, contentHash)
		// signature
		ih = newInnerHeader(signatureType, true, sig[:])
		if err := ih.write(&buf); err != nil {
			return err
		}
		// padding
		padLen := MaxContentLength - len(content)
		pad, err := padding.Generate(padLen, cipher.RandReader)
		if err != nil {
			return err
		}
		ih = newInnerHeader(paddingType, false, pad)
		if err := ih.write(&buf); err != nil {
			return err
		}
	} else {
		// just padding
		padLen := MaxContentLength + signatureSize - encryptedPacketSize +
			innerHeaderSize - len(content)
		pad, err := padding.Generate(padLen, cipher.RandReader)
		if err != nil {
			return err
		}
		ih = newInnerHeader(paddingType, false, pad)
		if err := ih.write(&buf); err != nil {
			return err
		}
	}
	// encrypt inner header
	stream.XORKeyStream(buf.Bytes(), buf.Bytes())
	oh = newOuterHeader(encryptedPacket, count, buf.Bytes())
	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// continue HMAC calculation
	if err := oh.write(mac, true); err != nil {
		return err
	}

	// create HMAC header
	oh = newOuterHeader(hmacPacket, count, nil)
	oh.PLen = sha512.Size
	if err := oh.write(mac, false); err != nil {
		return err
	}
	oh.inner = mac.Sum(oh.inner)
	log.Debugf("HMAC:       %s", base64.Encode(oh.inner))
	if err := oh.write(wc, true); err != nil {
		return err
	}
	count++

	// write output
	wc.Close()
	if out.Len() != EncodedMsgSize {
		return log.Errorf("out.Len() = %d != %d = EncodedMsgSize)",
			out.Len(), EncodedMsgSize)
	}
	if _, err := io.Copy(args.Writer, &out); err != nil {
		return log.Error(err)
	}

	// delete message key
	err = args.KeyStore.DelMessageKey(myID, contactID, true,
		ss.SenderMessageCount)
	if err != nil {
		return err
	}
	// increase SenderMessageCount
	ss.SenderMessageCount++
	err = args.KeyStore.SetSessionState(myID, contactID, ss)
	if err != nil {
		return err
	}

	return nil
}
