// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uid

import (
	"encoding/json"
	"io"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/util"
	"github.com/mutecomm/mute/util/times"
)

// A SessionAnchor contains the keys for perfect forward secrecy.
type SessionAnchor struct {
	MIXADDRESS string     // fully qualified address of mix to use as last hop to user
	NYMADDRESS string     // a valid NymAddress
	PFKEYS     []KeyEntry // for ephemeral/forward secure key agreement
}

type contents struct {
	VERSION           string // the protocol version
	MSGCOUNT          uint64 // must increase for each message of the same type and user
	NOTAFTER          uint64 // time after which the key(s) should not be used anymore
	NOTBEFORE         uint64 // time before which the key(s) should not be used yet
	FALLBACK          bool   // determines if the key may serve as a fallback key
	SIGKEYHASH        string // SHA512(UIDMessage.UIDContent.SIGKEY.HASH)
	REPOURI           string // URI of the corresponding KeyInit repository
	SESSIONANCHOR     string // SESSIONANCHOR = AES256_CTR(key=UIDMessage.UIDContent.SIGKEY.HASH, SessionAnchor)
	SESSIONANCHORHASH string // before encryption
}

// A KeyInit message contains short-term keys.
type KeyInit struct {
	CONTENTS  contents
	SIGNATURE string // signature of contents by UIDMessage.UIDContent.SIGKEY
}

// The number of seconds the NOTAFTER field of a KeyInit message can be in the
// future.
const MaxNotAfter = uint64(90 * 24 * 60 * 60) // 90 days

// NewJSONKeyInit returns a new KeyInit message initialized with the parameters
// given in the JSON byte array.
func NewJSONKeyInit(keyInit []byte) (*KeyInit, error) {
	var ki KeyInit
	if err := json.Unmarshal(keyInit, &ki); err != nil {
		return nil, err
	}
	return &ki, nil
}

func (sa *SessionAnchor) json() []byte {
	return marshalSorted(sa)
}

// PrivateKey returns the base64 encoded private signature key of
// session anchor.
func (sa *SessionAnchor) PrivateKey() string {
	return base64.Encode(sa.PFKEYS[0].PrivateKey32()[:])
}

// SetPrivateKey sets the private key to the given base64 encoded privkey
// string.
func (sa *SessionAnchor) SetPrivateKey(privkey string) error {
	key, err := base64.Decode(privkey)
	if err != nil {
		return err
	}
	return sa.PFKEYS[0].setPrivateKey(key)
}

// KeyEntry returns the KeyEntry of the SessionAnchor for the given function.
func (sa *SessionAnchor) KeyEntry(function string) (*KeyEntry, error) {
	for _, ke := range sa.PFKEYS {
		if ke.FUNCTION == function {
			return &ke, nil
		}
	}
	log.Error(ErrKeyEntryNotFound)
	return nil, ErrKeyEntryNotFound
}

// NymAddress returns the nymaddress of the SessionAnchor.
func (sa *SessionAnchor) NymAddress() string {
	return sa.NYMADDRESS
}

func (c *contents) json() []byte {
	return marshalSorted(c)
}

// JSON encodes KeyInit as a JSON string according to the specification.
func (ki *KeyInit) JSON() []byte {
	return marshalSorted(ki)
}

// MsgCount returns the message count of the KeyInit message.
func (ki *KeyInit) MsgCount() uint64 {
	return ki.CONTENTS.MSGCOUNT
}

// SigKeyHash returns the signature key hash of the KeyInit message.
func (ki *KeyInit) SigKeyHash() string {
	return ki.CONTENTS.SIGKEYHASH
}

// SessionAnchor returns the decrypted and verified session anchor for KeyInit.
func (ki *KeyInit) SessionAnchor(sigPubKey string) (*SessionAnchor, error) {
	// SIGKEYHASH corresponds to the SIGKEY of the Identity
	pubKey, err := base64.Decode(sigPubKey)
	if err != nil {
		return nil, err
	}
	keyHash := cipher.SHA512(pubKey)
	if ki.CONTENTS.SIGKEYHASH != base64.Encode(cipher.SHA512(keyHash)) {
		log.Error(ErrWrongSigKeyHash)
		return nil, ErrWrongSigKeyHash
	}
	// verify that SESSIONANCHORHASH matches decrypted SESSIONANCHOR
	enc, err := base64.Decode(ki.CONTENTS.SESSIONANCHOR)
	if err != nil {
		return nil, err
	}
	txt := cipher.AES256CTRDecrypt(keyHash[:32], enc)
	var sa SessionAnchor
	if err := json.Unmarshal(txt, &sa); err != nil {
		return nil, err
	}
	if ki.CONTENTS.SESSIONANCHORHASH != base64.Encode(cipher.SHA512(sa.json())) {
		log.Error(ErrSessionAnchor)
		return nil, ErrSessionAnchor
	}
	return &sa, nil
}

// KeyEntryECDHE25519 returns the decrypted and verified ECDHE25519 KeyEntry
// for KeyInit.
func (ki *KeyInit) KeyEntryECDHE25519(sigPubKey string) (*KeyEntry, error) {
	sa, err := ki.SessionAnchor(sigPubKey)
	if err != nil {
		return nil, err
	}
	ke, err := sa.KeyEntry("ECDHE25519")
	if err != nil {
		return nil, err
	}
	return ke, err
}

// Verify verifies that the KeyInit is valid.
func (ki *KeyInit) Verify(keyInitRepositoryURIs []string, sigPubKey string) error {
	// The REPOURI points to this KeyInit Repository
	if !util.ContainsString(keyInitRepositoryURIs, ki.CONTENTS.REPOURI) {
		log.Error(ErrRepoURI)
		return ErrRepoURI
	}

	// verify that SESSIONANCHORHASH matches decrypted SESSIONANCHOR
	if _, err := ki.SessionAnchor(sigPubKey); err != nil {
		return err
	}

	// NOTAFTER and NOTBEFORE are valid
	if ki.CONTENTS.NOTBEFORE >= ki.CONTENTS.NOTAFTER {
		log.Error(ErrInvalidTimes)
		return ErrInvalidTimes
	}
	// not expired
	if ki.CONTENTS.NOTAFTER < uint64(times.Now()) {
		log.Error(ErrExpired)
		return ErrExpired
	}

	// SIGNATURE was made with UIDMessage.UIDContent.SIGKEY over Contents
	var ed25519Key cipher.Ed25519Key
	sig, err := base64.Decode(ki.SIGNATURE)
	if err != nil {
		return err
	}
	pubKey, err := base64.Decode(sigPubKey)
	if err != nil {
		return err
	}
	// create ed25519 key
	ed25519Key.SetPublicKey(pubKey)
	// verify self-signature
	if !ed25519Key.Verify(ki.CONTENTS.json(), sig) {
		log.Error(ErrInvalidKeyInitSig)
		return ErrInvalidKeyInitSig
	}

	return nil
}

// Sign signs the KeyInit message and returns the signature.
func (ki *KeyInit) Sign(sigKey *cipher.Ed25519Key) string {
	return base64.Encode(sigKey.Sign(ki.JSON()))
}

// VerifySrvSig verifies the signature with the srvPubKey.
func (ki *KeyInit) VerifySrvSig(signature, srvPubKey string) error {
	var ed25519Key cipher.Ed25519Key
	// get server-signature
	sig, err := base64.Decode(signature)
	if err != nil {
		return err
	}
	// create ed25519 key
	pubKey, err := base64.Decode(srvPubKey)
	if err != nil {
		return err
	}
	ed25519Key.SetPublicKey(pubKey)
	// verify server-signature
	if !ed25519Key.Verify(ki.JSON(), sig) {
		log.Error(ErrInvalidSrvSig)
		return ErrInvalidSrvSig
	}
	return nil
}

func (msg *Message) sessionAnchor(
	key []byte,
	mixaddress, nymaddress string,
	rand io.Reader,
) (sessionAnchor, sessionAnchorHash, pubKeyHash, privateKey string, err error) {
	var sa SessionAnchor
	sa.MIXADDRESS = mixaddress
	sa.NYMADDRESS = nymaddress
	sa.PFKEYS = make([]KeyEntry, 1)
	if err := sa.PFKEYS[0].InitDHKey(rand); err != nil {
		return "", "", "", "", err
	}
	jsn := sa.json()
	hash := cipher.SHA512(jsn)
	// SESSIONANCHOR = AES256_CTR(key=UIDMessage.UIDContent.SIGKEY.HASH, SessionAnchor)
	enc := base64.Encode(cipher.AES256CTREncrypt(key[:32], jsn, rand))
	return enc, base64.Encode(hash), sa.PFKEYS[0].HASH, base64.Encode(sa.PFKEYS[0].PrivateKey32()[:]), nil
}

// KeyInit returns a new KeyInit message for the given UID message. It also
// returns the pubKeyHash and privateKey for convenient further use.
// msgcount must increase for each message of the same type and user.
// notafter is the unixtime after which the key(s) should not be used anymore.
// notbefore is the unixtime before which the key(s) should not be used yet.
// fallback determines if the key may serve as a fallback key.
// repouri is URI of the corresponding KeyInit repository.
// Necessary randomness is read from rand.
func (msg *Message) KeyInit(
	msgcount, notafter, notbefore uint64,
	fallback bool,
	repouri, mixaddress, nymaddress string,
	rand io.Reader,
) (ki *KeyInit, pubKeyHash, privateKey string, err error) {
	var keyInit KeyInit
	// time checks
	if notbefore >= notafter {
		log.Error(ErrInvalidTimes)
		return nil, "", "", ErrInvalidTimes
	}
	if notafter < uint64(times.Now()) {
		log.Error(ErrExpired)
		return nil, "", "", ErrExpired
	}
	if notafter > uint64(times.Now())+MaxNotAfter {
		log.Error(ErrFuture)
		return nil, "", "", ErrFuture
	}
	// init
	keyInit.CONTENTS.VERSION = ProtocolVersion
	keyInit.CONTENTS.MSGCOUNT = msgcount
	keyInit.CONTENTS.NOTAFTER = notafter
	keyInit.CONTENTS.NOTBEFORE = notbefore
	keyInit.CONTENTS.FALLBACK = fallback
	keyHash, err := base64.Decode(msg.UIDContent.SIGKEY.HASH)
	if err != nil {
		return nil, "", "", err
	}
	keyInit.CONTENTS.SIGKEYHASH = base64.Encode(cipher.SHA512(keyHash))
	keyInit.CONTENTS.REPOURI = repouri
	// create SessionAnchor
	sa, sah, pubKeyHash, privateKey, err := msg.sessionAnchor(keyHash,
		mixaddress, nymaddress, rand)
	if err != nil {
		return nil, "", "", err
	}
	keyInit.CONTENTS.SESSIONANCHOR = sa
	keyInit.CONTENTS.SESSIONANCHORHASH = sah
	// sign KeyInit: the content doesn't have to be hashed, because Ed25519 is
	// already taking care of that.
	sig := msg.UIDContent.SIGKEY.ed25519Key.Sign(keyInit.CONTENTS.json())
	keyInit.SIGNATURE = base64.Encode(sig)
	ki = &keyInit
	return
}
