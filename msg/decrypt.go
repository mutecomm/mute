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
	"github.com/mutecomm/mute/msg/mime"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

func rootKeyAgreementRecipient(
	senderIdentity, recipientIdentity string,
	senderSession, senderID, recipientKI, recipientID *uid.KeyEntry,
	previousRootKeyHash *[64]byte,
	numOfKeys uint64,
	keyStore session.Store,
) error {
	recipientIdentityPub := recipientID.PublicKey32()
	recipientIdentityPriv := recipientID.PrivateKey32()
	recipientKeyInitPub := recipientKI.PublicKey32()
	recipientKeyInitPriv := recipientKI.PrivateKey32()
	// sender cannot cause panic here, because keys have been validated in header
	senderSessionPub := senderSession.PublicKey32()
	senderIdentityPub := senderID.PublicKey32()

	log.Debugf("senderIdentityPub:    %s", base64.Encode(senderIdentityPub[:]))
	log.Debugf("senderSessionPub:     %s", base64.Encode(senderSessionPub[:]))
	log.Debugf("recipientIdentityPub: %s", base64.Encode(recipientIdentityPub[:]))
	log.Debugf("recipientKeyInitPub:  %s", base64.Encode(recipientKeyInitPub[:]))

	// check keys to prevent reflection attacks
	err := checkKeys(senderIdentityPub, senderSessionPub,
		recipientIdentityPub, recipientKeyInitPub)
	if err != nil {
		return err
	}

	// compute t1
	t1, err := cipher.ECDH(recipientKeyInitPriv, senderIdentityPub, recipientKeyInitPub)
	if err != nil {
		return err
	}

	// compute t2
	t2, err := cipher.ECDH(recipientKeyInitPriv, senderSessionPub, recipientKeyInitPub)
	if err != nil {
		return err
	}

	// compute t3
	t3, err := cipher.ECDH(recipientIdentityPriv, senderSessionPub, recipientIdentityPub)
	if err != nil {
		return err
	}

	// derive root key
	rootKey, err := deriveRootKey(t1, t2, t3, previousRootKeyHash)
	if err != nil {
		return err
	}

	// generate message keys
	err = generateMessageKeys(senderIdentity, recipientIdentity, rootKey[:],
		true, senderSessionPub, recipientKeyInitPub, numOfKeys, keyStore)
	if err != nil {
		return err
	}
	return nil
}

// DecryptArgs contains all arguments for a message decryption.
type DecryptArgs struct {
	Writer              io.Writer       // decrypted message is written here
	Identities          []string        // list of recipient identity strings
	RecipientIdentities []*uid.KeyEntry // list of recipient identity KeyEntries
	PreHeader           []byte          // preHeader read with ReadFirstOuterHeader()
	Reader              io.Reader       // data to decrypt is read here (not base64 encoded)
	NumOfKeys           uint64          // number of generated sessions keys (default: NumOfFutureKeys)
	Rand                io.Reader       // random source
	KeyStore            session.Store   // for managing session keys
}

// Decrypt decrypts a message with the argument given in args.
// The senderID is returned.
// If the message was signed and the signature could be verified successfully
// the base64 encoded signature is returned. If the message was signed and the
// signature could not be verfied an error is returned.
func Decrypt(args *DecryptArgs) (senderID, sig string, err error) {
	log.Debug("msg.Decrypt()")

	// set default
	if args.NumOfKeys == 0 {
		args.NumOfKeys = NumOfFutureKeys
	}

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

	log.Debugf("senderID:    %s", h.SenderIdentityPub.HASH)
	log.Debugf("recipientID: %s", recipientID.HASH)
	log.Debugf("h.SenderSessionCount: %d", h.SenderSessionCount)
	log.Debugf("h.SenderMessageCount: %d", h.SenderMessageCount)
	log.Debugf("h.SenderSessionPub:             %s", h.SenderSessionPub.HASH)
	log.Debugf("h.NextSenderSessionPub:         %s", h.NextSenderSessionPub.HASH)
	if h.NextRecipientSessionPubSeen != nil {
		log.Debugf("h.NextRecipientSessionPubSeen:  %s",
			h.NextRecipientSessionPubSeen.HASH)
	}

	// proc sender UID in parallel
	res := make(chan *procUIDResult, 1)
	go procUID(h.SenderUID, res)

	// get session state
	sender := h.SenderIdentity
	recipient := args.Identities[i]
	log.Debugf("%s -> %s", sender, recipient)
	ss, err := args.KeyStore.GetSessionState(recipient, sender)
	if err != nil {
		return "", "", err
	}
	if ss == nil {
		// no session found -> start first session
		log.Debug("no session found -> start first session")
		// root key agreement
		recipientKI, err := args.KeyStore.GetPrivateKeyEntry(h.RecipientTempHash)
		if err != nil {
			return "", "", err
		}
		err = rootKeyAgreementRecipient(sender, recipient,
			&h.SenderSessionPub, &h.SenderIdentityPub, recipientKI, recipientID,
			nil, args.NumOfKeys, args.KeyStore)
		if err != nil {
			return "", "", err
		}
		// create next session key
		var nextSenderSession uid.KeyEntry
		if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
			return "", "", err
		}
		// set session state
		ss = &session.State{
			SenderSessionCount:          0,
			SenderMessageCount:          0,
			RecipientSessionCount:       0,
			RecipientMessageCount:       0,
			RecipientTemp:               h.SenderSessionPub,
			SenderSessionPub:            *recipientKI,
			NextSenderSessionPub:        &nextSenderSession,
			NextRecipientSessionPubSeen: h.NextSenderSessionPub,
		}
		log.Debugf("set session: %s", ss.SenderSessionPub.HASH)
		err = args.KeyStore.SetSessionState(recipient, sender, ss)
		if err != nil {
			return "", "", err
		}
	} else {
		log.Debug("session found")
		log.Debugf("got session: %s", ss.SenderSessionPub.HASH)
		// make sure the new session key of the other party is up-to-date.
		if h.NextSenderSessionPub != nil &&
			ss.NextRecipientSessionPubSeen != h.NextSenderSessionPub {
			if ss.NextRecipientSessionPubSeen != nil {
				log.Debugf("ss.NextRecipientSessionPubSeen: %s",
					ss.NextRecipientSessionPubSeen.HASH)
			}
			ss.NextRecipientSessionPubSeen = h.NextSenderSessionPub
			err = args.KeyStore.SetSessionState(recipient, sender, ss)
			log.Debug("update session key")
			if err != nil {
				return "", "", err
			}
		}
		// check if the session was refreshed (on the other side)
		if h.RecipientTempHash != ss.SenderSessionPub.HASH &&
			!args.KeyStore.HasSession(recipient, sender, h.RecipientTempHash) { // make sure session is unknown
			log.Debug("session was refreshed (on the other side)")
			// check if sessions have been started simultaneously
			if h.RecipientTempHash != ss.NextSenderSessionPub.HASH {
				// start session on this side as well to be able to decrypt
				log.Debug("sessions started simultaneously")
				// root key agreement
				recipientKI, err := args.KeyStore.GetPrivateKeyEntry(h.RecipientTempHash)
				if err != nil {
					// TODO: reset session here?
					return "", "", err
				}
				err = rootKeyAgreementRecipient(sender, recipient,
					&h.SenderSessionPub, &h.SenderIdentityPub, recipientKI, recipientID,
					nil, args.NumOfKeys, args.KeyStore)
				if err != nil {
					return "", "", err
				}
				// use the 'smaller' session as the definite one
				// TODO: h.SenderSessionPub.HASH < ss.SenderSessionPub.HASH {
				if sender < recipient {
					log.Debug("use the 'smaller' session as definite one")
					// TODO: extract method from this block?
					// create next session key
					var nextSenderSession uid.KeyEntry
					if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
						return "", "", err
					}
					// set session state
					ss = &session.State{
						SenderSessionCount:          0,
						SenderMessageCount:          0,
						RecipientSessionCount:       0,
						RecipientMessageCount:       0,
						RecipientTemp:               h.SenderSessionPub,
						SenderSessionPub:            *recipientKI,
						NextSenderSessionPub:        &nextSenderSession,
						NextRecipientSessionPubSeen: h.NextSenderSessionPub,
					}
					log.Debugf("set session: %s", ss.SenderSessionPub.HASH)
					err = args.KeyStore.SetSessionState(recipient, sender, ss)
					if err != nil {
						return "", "", err
					}
				} else {
					log.Debug("session is 'larger', keep old one")
				}
			} else { // session was refreshed on other side
				log.Debug("create new session")
				// make sure we have the correct key
				if ss.NextSenderSessionPub == nil ||
					h.NextRecipientSessionPubSeen == nil ||
					!uid.KeyEntryEqual(ss.NextSenderSessionPub,
						h.NextRecipientSessionPubSeen) {
					// TODO: reset session here?
					return "", "", log.Error("msg: NextSenderSessionPub mismatch")
				}
				ss.RecipientTemp = h.SenderSessionPub
				previousRootKeyHash, err := args.KeyStore.GetRootKeyHash(recipient,
					sender, ss.SenderSessionPub.HASH)
				if err != nil {
					return "", "", err
				}
				ss.SenderSessionPub = *ss.NextSenderSessionPub
				var nextSenderSession uid.KeyEntry
				if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
					return "", "", err
				}
				ss.NextSenderSessionPub = &nextSenderSession
				ss.SenderSessionCount = ss.SenderSessionCount + ss.SenderMessageCount
				ss.SenderMessageCount = 0
				ss.RecipientSessionCount = h.SenderSessionCount
				ss.RecipientMessageCount = h.SenderMessageCount
				// root key agreement
				err = rootKeyAgreementSender(recipient, sender,
					&ss.SenderSessionPub, recipientID,
					&h.SenderSessionPub, &h.SenderIdentityPub,
					previousRootKeyHash, args.NumOfKeys, args.KeyStore)
				if err != nil {
					return "", "", err
				}
				// store new session state
				err = args.KeyStore.SetSessionState(recipient, sender, ss)
				if err != nil {
					return "", "", err
				}
			}
		} else if h.NextSenderSessionPub != nil && // check if we have to refresh the session (on our side)
			h.NextRecipientSessionPubSeen != nil &&
			uid.KeyEntryEqual(ss.NextSenderSessionPub, h.NextRecipientSessionPubSeen) {
			// sender has sent next session key and own next session key
			// has been reflected -> refresh session
			log.Debug("refresh session")
			ss.RecipientTemp = *h.NextSenderSessionPub
			previousRootKeyHash, err := args.KeyStore.GetRootKeyHash(recipient,
				sender, ss.SenderSessionPub.HASH)
			if err != nil {
				return "", "", err
			}
			ss.SenderSessionPub = *ss.NextSenderSessionPub
			var nextSenderSession uid.KeyEntry
			if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
				return "", "", err
			}
			ss.NextSenderSessionPub = &nextSenderSession
			ss.SenderSessionCount = ss.SenderSessionCount + ss.SenderMessageCount
			ss.SenderMessageCount = 0
			ss.RecipientSessionCount = h.SenderSessionCount + h.SenderMessageCount
			ss.RecipientMessageCount = 0
			// root key agreement
			err = rootKeyAgreementRecipient(sender, recipient,
				h.NextSenderSessionPub, &h.SenderIdentityPub,
				&ss.SenderSessionPub, recipientID,
				previousRootKeyHash, args.NumOfKeys, args.KeyStore)
			if err != nil {
				return "", "", err
			}
			// store new session state
			err = args.KeyStore.SetSessionState(recipient, sender, ss)
			if err != nil {
				return "", "", err
			}
		} else {
			log.Debug("refresh not possible")
		}
	}

	// make sure we got enough message keys
	n, err := args.KeyStore.NumMessageKeys(recipient, sender,
		h.RecipientTempHash)
	if err != nil {
		return "", "", err
	}
	if h.SenderMessageCount >= n {
		// generate more message keys
		log.Debugf("generate more message keys (h.SenderMessageCount=%d, n=%d)",
			h.SenderMessageCount, n)
		chainKey, err := args.KeyStore.GetChainKey(recipient, sender,
			h.RecipientTempHash)
		if err != nil {
			return "", "", err
		}
		// prevent denial of service attack by very large h.SenderMessageCount
		numOfKeys := h.SenderMessageCount / args.NumOfKeys
		if h.SenderMessageCount%args.NumOfKeys > 0 {
			numOfKeys++
		}
		numOfKeys *= args.NumOfKeys
		if numOfKeys > mime.MaxMsgSize/MaxContentLength+NumOfFutureKeys {
			return "", "",
				log.Errorf("msg: requested number of message keys too large")
		}
		log.Debugf("numOfKeys=%d", numOfKeys)
		var recipientPub *[32]byte
		if h.RecipientTempHash == ss.SenderSessionPub.HASH {
			recipientPub = ss.SenderSessionPub.PublicKey32()
		} else {
			log.Debug("different session")
			recipientKI, err := args.KeyStore.GetPrivateKeyEntry(h.RecipientTempHash)
			if err != nil {
				return "", "", err
			}
			recipientPub = recipientKI.PublicKey32()
		}
		err = generateMessageKeys(sender, recipient, chainKey[:], true,
			h.SenderSessionPub.PublicKey32(), recipientPub, numOfKeys,
			args.KeyStore)
		if err != nil {
			return "", "", err
		}
	}

	// get message key
	messageKey, err := args.KeyStore.GetMessageKey(recipient, sender,
		h.RecipientTempHash, false, h.SenderMessageCount)
	if err != nil {
		return "", "", err
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := deriveSymmetricKeys(messageKey)
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

	// delete message key
	err = args.KeyStore.DelMessageKey(recipient, sender,
		h.RecipientTempHash, false, h.SenderMessageCount)
	if err != nil {
		return "", "", err
	}
	// TODO: change ss.RecipientMessageCount?

	return
}
