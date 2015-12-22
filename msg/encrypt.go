// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/padding"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

func rootKeyAgreementSender(
	senderHeaderPub *[32]byte,
	senderIdentity, recipientIdentity string,
	senderSession, senderID, recipientKI, recipientID *uid.KeyEntry,
	previousRootKeyHash *[64]byte,
	numOfKeys uint64,
	keyStore session.Store,
) error {
	senderIdentityPub := senderID.PublicKey32()
	senderIdentityPriv := senderID.PrivateKey32()
	senderSessionPub := senderSession.PublicKey32()
	senderSessionPriv := senderSession.PrivateKey32()
	recipientIdentityPub := recipientID.PublicKey32()
	recipientKeyInitPub := recipientKI.PublicKey32()

	log.Debugf("senderIdentityPub:    %s", base64.Encode(senderIdentityPub[:]))
	log.Debugf("senderSessionPub:     %s", base64.Encode(senderSessionPub[:]))
	log.Debugf("recipientIdentityPub: %s", base64.Encode(recipientIdentityPub[:]))
	log.Debugf("recipientKeyInitPub:  %s", base64.Encode(recipientKeyInitPub[:]))

	// check keys to prevent reflection attacks and replays
	err := checkKeys(senderHeaderPub, senderIdentityPub, senderSessionPub,
		recipientIdentityPub, recipientKeyInitPub)
	if err != nil {
		return err
	}

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
	err = generateMessageKeys(senderIdentity, recipientIdentity,
		senderID.HASH, recipientID.HASH, rootKey, false, senderSessionPub,
		recipientKeyInitPub, numOfKeys, keyStore)
	if err != nil {
		return err
	}
	return nil
}

// EncryptArgs contains all arguments for a message encryption.
type EncryptArgs struct {
	Writer                 io.Writer     // encrypted messagte is written here (base64 encoded)
	From                   *uid.Message  // sender UID
	To                     *uid.Message  // recipient UID
	SenderLastKeychainHash string        // last hash chain entry known to the sender
	PrivateSigKey          *[64]byte     // if this is s not nil the message is signed with the key
	Reader                 io.Reader     // data to encrypt is read here (only for StatusCode == StatusOK)
	NumOfKeys              uint64        // number of generated sessions keys (default: NumOfFutureKeys)
	AvgSessionSize         uint          // average session size (default: AverageSessionSize)
	Rand                   io.Reader     // random source
	KeyStore               session.Store // for managing session keys
	StatusCode             StatusCode    // status code of the encrypted message
}

// Encrypt encrypts a message with the argument given in args and returns the
// nymAddress the message should be delivered to.
func Encrypt(args *EncryptArgs) (nymAddress string, err error) {
	log.Debugf("msg.Encrypt(): %s -> %s", args.From.Identity(), args.To.Identity())

	// set defaults
	if args.NumOfKeys == 0 {
		args.NumOfKeys = NumOfFutureKeys
	}
	if args.AvgSessionSize == 0 {
		args.AvgSessionSize = AverageSessionSize
	}

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
	sessionStateKey := session.CalcStateKey(args.From.PubKey().PublicKey32(),
		args.To.PubKey().PublicKey32())
	var ss *session.State
	if args.StatusCode != StatusReset {
		ss, err = args.KeyStore.GetSessionState(sessionStateKey)
		if err != nil {
			return "", err
		}
	}
	if ss == nil {
		// no session found -> start first session
		log.Debug("no session found -> start first session")
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
		// store session key
		if err := addSessionKey(args.KeyStore, &senderSession); err != nil {
			return "", err
		}
		// root key agreement
		err = rootKeyAgreementSender(senderHeaderKey.PublicKey(),
			args.From.Identity(), args.To.Identity(), &senderSession,
			args.From.PubKey(), recipientTemp, args.To.PubKey(), nil,
			args.NumOfKeys, args.KeyStore)
		if err != nil {
			return "", err
		}
		// set session state
		ss = &session.State{
			SenderSessionCount:          0,
			SenderMessageCount:          0,
			MaxRecipientCount:           0,
			RecipientTemp:               *recipientTemp,
			SenderSessionPub:            senderSession,
			NextSenderSessionPub:        nil,
			NextRecipientSessionPubSeen: nil,
			NymAddress:                  nymAddress,
		}
		log.Debugf("set session: %s", ss.SenderSessionPub.HASH)
		err = args.KeyStore.SetSessionState(sessionStateKey, ss)
		if err != nil {
			return "", err
		}
	} else if args.StatusCode != StatusError { // do not update sessions for StatusError messages
		log.Debug("session found")
		log.Debugf("got session: %s", ss.SenderSessionPub.HASH)
		nymAddress = ss.NymAddress
		// start new session in randomized fashion
		n, err := rand.Int(cipher.RandReader, big.NewInt(int64(args.AvgSessionSize)))
		if err != nil {
			return "", err
		}
		if n.Int64() == 0 {
			// create next session key
			var nextSenderSession uid.KeyEntry
			if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
				return "", err
			}
			// store next session key
			if err := addSessionKey(args.KeyStore, &nextSenderSession); err != nil {
				return "", err
			}
			// update session state
			ss.NextSenderSessionPub = &nextSenderSession
			log.Debugf("set session: %s", ss.SenderSessionPub.HASH)
			err = args.KeyStore.SetSessionState(sessionStateKey, ss)
			if err != nil {
				return "", err
			}
		}
	}

	// create header
	log.Debugf("senderID:    %s", args.From.UIDContent.PUBKEYS[0].HASH)
	log.Debugf("recipientID: %s", args.To.UIDContent.PUBKEYS[0].HASH)
	log.Debugf("ss.SenderSessionCount: %d", ss.SenderSessionCount)
	log.Debugf("ss.SenderMessageCount: %d", ss.SenderMessageCount)
	log.Debugf("ss.RecipientTempHash:  %s", ss.RecipientTemp.HASH)
	h, err := newHeader(args.From, args.To, ss.RecipientTemp.HASH,
		&ss.SenderSessionPub, ss.NextSenderSessionPub,
		ss.NextRecipientSessionPubSeen, ss.SenderSessionCount,
		ss.SenderMessageCount, args.SenderLastKeychainHash, args.Rand,
		args.StatusCode)
	if err != nil {
		return "", err
	}
	log.Debugf("h.SenderSessionPub:             %s", h.SenderSessionPub.HASH)
	if h.NextSenderSessionPub != nil {
		log.Debugf("h.NextSenderSessionPub:         %s", h.NextSenderSessionPub.HASH)
	}
	if h.NextRecipientSessionPubSeen != nil {
		log.Debugf("h.NextRecipientSessionPubSeen:  %s",
			h.NextRecipientSessionPubSeen.HASH)
	}

	// create (encrypted) header packet
	recipientIdentityPub, err := args.To.PublicKey()
	if err != nil {
		return "", err
	}

	hp, err := newHeaderPacket(h, recipientIdentityPub,
		senderHeaderKey.PrivateKey(), args.Rand)
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

	sessionKey := session.CalcKey(args.From.PubKey().HASH,
		args.To.PubKey().HASH, ss.SenderSessionPub.HASH, ss.RecipientTemp.HASH)

	// make sure we got enough message keys
	n, err := args.KeyStore.NumMessageKeys(sessionKey)
	if err != nil {
		return "", err
	}
	if ss.SenderMessageCount >= n {
		// generate more message keys
		log.Debugf("generate more message keys (ss.SenderMessageCount=%d)",
			ss.SenderMessageCount)
		chainKey, err := args.KeyStore.GetChainKey(sessionKey)
		if err != nil {
			return "", err
		}

		err = generateMessageKeys(sender, recipient, args.From.PubKey().HASH,
			args.To.PubKey().HASH, chainKey, false,
			ss.SenderSessionPub.PublicKey32(), ss.RecipientTemp.PublicKey32(),
			args.NumOfKeys, args.KeyStore)
		if err != nil {
			return "", err
		}
	}

	// get message key
	messageKey, err := args.KeyStore.GetMessageKey(sessionKey, true,
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
	var content []byte
	if args.StatusCode == StatusOK { // StatusReset and StatusError messages are empty
		content, err = ioutil.ReadAll(args.Reader)
		if err != nil {
			return "", log.Error(err)
		}
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
	err = args.KeyStore.DelMessageKey(sessionKey, true, ss.SenderMessageCount)
	if err != nil {
		return "", err
	}
	// increase SenderMessageCount
	ss.SenderMessageCount++
	err = args.KeyStore.SetSessionState(sessionStateKey, ss)
	if err != nil {
		return "", err
	}

	return
}
