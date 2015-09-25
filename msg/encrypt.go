package msg

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"io"
	"io/ioutil"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"

	"github.com/agl/ed25519"
)

func rootKeyAgreementSender(
	senderID, recipientID *uid.Message,
	senderSession, recipientKI *uid.KeyEntry,
	previousRootKeyHash []byte,
	storeSession StoreSession,
) ([]byte, error) {
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
	messageKey, err := generateMessageKeys(senderID.Identity(),
		recipientID.Identity(), rootKey, senderSessionPub[:],
		recipientKeyInitPub[:], storeSession)
	if err != nil {
		return nil, err
	}

	return messageKey, nil
}

// EncryptArgs contains all arguments for a message encryption.
//
// TODO: document stuff in detail
type EncryptArgs struct {
	Writer                      io.Writer
	From                        *uid.Message
	To                          *uid.Message
	RecipientTemp               *uid.KeyEntry
	NextSenderSessionPub        *uid.KeyEntry
	NextRecipientSessionPubSeen *uid.KeyEntry
	SenderLastKeychainHash      string
	PreviousRootKeyHash         []byte
	PrivateSigKey               *[64]byte
	Reader                      io.Reader
	Rand                        io.Reader
	StoreSession                StoreSession
}

// Encrypt reads data from r, encrypts it for UID message to (with UID message
// from as sender), and writes it to w.
// For the encryption recipientTemp has to be either RecipientKeyInitPub or
// RecipientSessionPub (if previous SenderSessionPub from other party has been
// received.)
// senderLastKeychainHash contains the last hash chain entry known to the sender.
// previousRootKeyHash has to contain the previous root key hash, if it exists.
// If privateSigKey is not nil the encrypted message is signed with the key
// and the signature is encoded in the message.
// Necessary randomness is read from rand.
// storeSession is called to store new session keys.
//
// TODO: document nextSenderSessionPub and nextRecipientSessionPubSeen.
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
	wc := base64.NewEncoder(args.Writer)
	defer wc.Close()

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
	var padding bool
	if args.PrivateSigKey != nil {
		padding = true
	}
	h, err := newHeader(args.From, args.To, args.RecipientTemp, &senderSession,
		args.NextSenderSessionPub, args.NextRecipientSessionPubSeen,
		args.SenderLastKeychainHash, padding, args.Rand)
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

	// root key agreement
	messageKey, err := rootKeyAgreementSender(args.From, args.To, &senderSession,
		args.RecipientTemp, args.PreviousRootKeyHash, args.StoreSession)
	if err != nil {
		return err
	}

	// derive symmetric keys
	cryptoKey, hmacKey, err := symmetricKeys(messageKey)
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
	// TODO: padding and streaming
	content, err := ioutil.ReadAll(args.Reader)
	if err != nil {
		return log.Error(err)
	}
	var contentHash []byte
	var innerType uint8
	if args.PrivateSigKey != nil {
		contentHash = cipher.SHA512(content)
		innerType = data | sign
	} else {
		innerType = data
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

	// signature header
	if args.PrivateSigKey != nil {
		sig := ed25519.Sign(args.PrivateSigKey, contentHash)
		ih = newInnerHeader(signature, false, sig[:])
		buf.Reset()
		if err := ih.write(&buf); err != nil {
			return err
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

	return nil
}
