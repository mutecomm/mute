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
	"github.com/mutecomm/mute/cipher/aes256"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/mime"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/uid"
)

func rootKeyAgreementRecipient(
	senderHeaderPub *[32]byte,
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

	// check keys to prevent reflection attacks and replays
	err := checkKeys(senderHeaderPub, senderIdentityPub, senderSessionPub,
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
	err = generateMessageKeys(senderIdentity, recipientIdentity,
		senderID.HASH, recipientID.HASH, rootKey, true, senderSessionPub,
		recipientKeyInitPub, numOfKeys, keyStore)
	if err != nil {
		return err
	}
	return nil
}

// DecryptArgs contains all arguments for a message decryption.
type DecryptArgs struct {
	Writer     io.Writer      // decrypted message is written here
	Identities []*uid.Message // list of recipient UID messages
	PreHeader  []byte         // preHeader read with ReadFirstOuterHeader()
	Reader     io.Reader      // data to decrypt is read here (not base64 encoded)
	NumOfKeys  uint64         // number of generated sessions keys (default: NumOfFutureKeys)
	Rand       io.Reader      // random source
	KeyStore   session.Store  // for managing session keys
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
	identity, h, err := readHeader(&senderHeaderPub, args.Identities,
		bytes.NewBuffer(oh.inner))
	if err != nil {
		return "", "", err
	}
	senderID = h.SenderIdentity
	recipientID := identity.PubKey()

	log.Debugf("senderID:    %s", h.SenderIdentityPub.HASH)
	log.Debugf("recipientID: %s", recipientID.HASH)
	log.Debugf("h.SenderSessionCount: %d", h.SenderSessionCount)
	log.Debugf("h.SenderMessageCount: %d", h.SenderMessageCount)
	log.Debugf("h.SenderSessionPub:             %s", h.SenderSessionPub.HASH)
	if h.NextSenderSessionPub != nil {
		log.Debugf("h.NextSenderSessionPub:         %s", h.NextSenderSessionPub.HASH)
	}
	if h.NextRecipientSessionPubSeen != nil {
		log.Debugf("h.NextRecipientSessionPubSeen:  %s",
			h.NextRecipientSessionPubSeen.HASH)
	}

	// proc sender UID in parallel
	res := make(chan *procUIDResult, 1)
	go procUID(h.SenderUID, res)

	// get session state
	sender := h.SenderIdentity
	recipient := identity.Identity()
	log.Debugf("%s -> %s", sender, recipient)
	sessionStateKey := session.CalcStateKey(recipientID.PublicKey32(),
		h.SenderIdentityPub.PublicKey32())
	ss, err := args.KeyStore.GetSessionState(sessionStateKey)
	if err != nil {
		return "", "", err
	}
	sessionKey := session.CalcKey(recipientID.HASH, h.SenderIdentityPub.HASH,
		h.RecipientTempHash, h.SenderSessionPub.HASH)

	if !args.KeyStore.HasSession(sessionKey) { // session unknown
		// try to start session from KeyInit message
		recipientKI, err := args.KeyStore.GetPrivateKeyEntry(h.RecipientTempHash)
		if err != nil && err != session.ErrNoKeyEntry {
			return "", "", err
		}
		if err != session.ErrNoKeyEntry { // KeyInit message found
			// root key agreement
			err = rootKeyAgreementRecipient(&senderHeaderPub, sender, recipient,
				&h.SenderSessionPub, &h.SenderIdentityPub, recipientKI, recipientID,
				nil, args.NumOfKeys, args.KeyStore)
			if err != nil {
				return "", "", err
			}

			// TODO: delete single-use KeyInit message

			// use the 'smaller' session as the definite one
			// TODO: h.SenderSessionPub.HASH < ss.SenderSessionPub.HASH
			if ss == nil || (ss.KeyInitSession && sender < recipient) {
				// create next session key
				var nextSenderSession uid.KeyEntry
				if err := nextSenderSession.InitDHKey(args.Rand); err != nil {
					return "", "", err
				}
				// store next session key
				err := addSessionKey(args.KeyStore, &nextSenderSession)
				if err != nil {
					return "", "", err
				}
				// if we already got h.NextSenderSessionPub prepare next session
				if h.NextSenderSessionPub != nil {
					previousRootKeyHash, err := args.KeyStore.GetRootKeyHash(sessionKey)
					if err != nil {
						return "", "", err
					}
					// root key agreement
					err = rootKeyAgreementSender(&senderHeaderPub, recipient,
						sender, &nextSenderSession, recipientID,
						h.NextSenderSessionPub, &h.SenderIdentityPub,
						previousRootKeyHash, args.NumOfKeys, args.KeyStore)
					if err != nil {
						return "", "", err
					}
				}
				// set session state
				ss = &session.State{
					SenderSessionCount:          0,
					SenderMessageCount:          0,
					MaxRecipientCount:           0,
					RecipientTemp:               h.SenderSessionPub,
					SenderSessionPub:            *recipientKI,
					NextSenderSessionPub:        &nextSenderSession,
					NextRecipientSessionPubSeen: h.NextSenderSessionPub,
					NymAddress:                  h.NymAddress,
					KeyInitSession:              false,
				}
				err = args.KeyStore.SetSessionState(sessionStateKey, ss)
				if err != nil {
					return "", "", err
				}
			}
		} else { // no KeyInit message found
			// TODO: ???
		}
	} else { // session known
		log.Debug("session known")
		// check if session state reflects that session
		if h.RecipientTempHash == ss.SenderSessionPub.HASH &&
			h.SenderSessionPub.HASH == ss.RecipientTemp.HASH {
			log.Debug("session state reflects that session")
			if h.NextSenderSessionPub != nil {
				log.Debug("h.NextSenderSessionPub is defined")
			}
			if h.NextRecipientSessionPubSeen != nil {
				log.Debug("h.NextRecipientSessionPubSeen is defined")
			}
			if h.NextSenderSessionPub != nil {
				// if other side has set its NextSenderSessionPubKey we set
				// ours immediately
				if ss.NextSenderSessionPub == nil {
					// prepare upcoming session, but do not switch to it yet
					nextSenderSession, err := setNextSenderSessionPub(args.KeyStore, ss,
						sessionStateKey, args.Rand)
					if err != nil {
						return "", "", err
					}
					previousRootKeyHash, err := args.KeyStore.GetRootKeyHash(sessionKey)
					if err != nil {
						return "", "", err
					}
					// root key agreement
					err = rootKeyAgreementSender(&senderHeaderPub, recipient,
						sender, nextSenderSession, recipientID,
						h.NextSenderSessionPub, &h.SenderIdentityPub,
						previousRootKeyHash, args.NumOfKeys, args.KeyStore)
					if err != nil {
						return "", "", err
					}
					if ss.NextRecipientSessionPubSeen == nil {
						// save h.NextSenderSessionPub, if necessary
						ss.NextRecipientSessionPubSeen = h.NextSenderSessionPub
						err := args.KeyStore.SetSessionState(sessionStateKey, ss)
						if err != nil {
							return "", "", err
						}
					}
				} else if h.NextRecipientSessionPubSeen != nil &&
					h.NextRecipientSessionPubSeen.HASH == ss.NextSenderSessionPub.HASH {
					// switch to next session
					nextSenderSession, err := getSessionKey(args.KeyStore,
						ss.NextSenderSessionPub.HASH)
					if err != nil {
						return "", "", err
					}
					previousRootKeyHash, err := args.KeyStore.GetRootKeyHash(sessionKey)
					if err != nil {
						return "", "", err
					}
					// root key agreement
					err = rootKeyAgreementRecipient(&senderHeaderPub, sender,
						recipient, h.NextSenderSessionPub, &h.SenderIdentityPub,
						nextSenderSession, recipientID, previousRootKeyHash,
						args.NumOfKeys, args.KeyStore)
					if err != nil {
						return "", "", err
					}
					// store new session state
					ss = &session.State{
						SenderSessionCount:          ss.SenderSessionCount + ss.SenderMessageCount,
						SenderMessageCount:          0,
						MaxRecipientCount:           0,
						RecipientTemp:               *h.NextSenderSessionPub,
						SenderSessionPub:            *nextSenderSession,
						NextSenderSessionPub:        nil,
						NextRecipientSessionPubSeen: nil,
						NymAddress:                  h.NymAddress,
						KeyInitSession:              false,
					}
					err = args.KeyStore.SetSessionState(sessionStateKey, ss)
					if err != nil {
						return "", "", err
					}
				}
			}
		} else {
			// check if session matches next session
			if ss.NextSenderSessionPub != nil &&
				ss.NextRecipientSessionPubSeen != nil &&
				ss.NextSenderSessionPub.HASH == h.RecipientTempHash &&
				ss.NextRecipientSessionPubSeen.HASH == h.SenderSessionPub.HASH {
				// switch session
				ss = &session.State{
					SenderSessionCount:          ss.SenderSessionCount + ss.SenderMessageCount,
					SenderMessageCount:          0,
					MaxRecipientCount:           0,
					RecipientTemp:               h.SenderSessionPub,
					SenderSessionPub:            *ss.NextSenderSessionPub,
					NextSenderSessionPub:        nil,
					NextRecipientSessionPubSeen: nil,
					NymAddress:                  h.NymAddress,
					KeyInitSession:              false,
				}
				err = args.KeyStore.SetSessionState(sessionStateKey, ss)
				if err != nil {
					return "", "", err
				}
			}
		}
		// a message with this session key has been decrypted -> delete key
		if err := args.KeyStore.DelPrivSessionKey(h.RecipientTempHash); err != nil {
			return "", "", err
		}
	}

	// make sure we got enough message keys
	n, err := args.KeyStore.NumMessageKeys(sessionKey)
	if err != nil {
		return "", "", err
	}
	if h.SenderMessageCount >= n {
		// generate more message keys
		log.Debugf("generate more message keys (h.SenderMessageCount=%d, n=%d)",
			h.SenderMessageCount, n)
		chainKey, err := args.KeyStore.GetChainKey(sessionKey)
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
			if err != nil && err != session.ErrNoKeyEntry {
				return "", "", err
			}
			if err != session.ErrNoKeyEntry {
				recipientPub = recipientKI.PublicKey32()
			} else {
				recipientKE, err := getSessionKey(args.KeyStore,
					h.RecipientTempHash)
				if err != nil {
					return "", "", err
				}
				recipientPub = recipientKE.PublicKey32()
			}
		}
		err = generateMessageKeys(sender, recipient, h.SenderIdentityPub.HASH,
			recipientID.HASH, chainKey, true,
			h.SenderSessionPub.PublicKey32(), recipientPub, numOfKeys,
			args.KeyStore)
		if err != nil {
			return "", "", err
		}
	}

	// get message key
	messageKey, err := args.KeyStore.GetMessageKey(sessionKey, false,
		h.SenderMessageCount)
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
	stream := aes256.CTRStream(cryptoKey, iv)
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

	// verify signature, if necessary
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
	err = args.KeyStore.DelMessageKey(sessionKey, false, h.SenderMessageCount)
	if err != nil {
		return "", "", err
	}

	return
}
