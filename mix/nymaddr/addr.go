// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nymaddr implements nym address generation and decoding.
package nymaddr

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/mutecomm/mute/mix/mixaddr"
	"github.com/mutecomm/mute/util/times"
	"github.com/ronperry/cryptoedge/lioness"
	"golang.org/x/crypto/curve25519"
)

var (
	// ErrNoMix is returned if no mix could be found.
	ErrNoMix = errors.New("nymaddr: no mix found")
	// ErrNoKey is returned if a private key was unavailable.
	ErrNoKey = errors.New("nymaddr: private key not found")
	// ErrExpired is returned if a nymaddr has already expired.
	ErrExpired = errors.New("nymaddr: expired")
	// ErrHMAC is returned if a nym-header HMAC verification failed.
	ErrHMAC = errors.New("nymaddr: HMAC mismatch")
	// ErrBadKey is returned if a header key is not reproduceable.
	ErrBadKey = errors.New("nymaddr: bad key in header")
)

// Rand is the random source of this package.
var Rand = rand.Reader

const (
	// KeySize is the size in bytes of a key for curve25519.
	KeySize = 32
)

// KeyFunc is a function that returns a private key for a public key, or nil.
type KeyFunc func(*[KeySize]byte) *[KeySize]byte

// Address contains a NymAddress.
type Address struct {
	MixAddress  []byte // The address of the mix which will handle messages for this Nym
	Expire      int64  // The time when the address should not be used anymore
	SingleUse   bool   // If the address may be used more than once
	TokenPubKey []byte // The token receive key of the mix
	MixPubKey   []byte // Public key of the mix
	AddressKey  []byte // Random, single use key used for this address
	PrivateData []byte // Encrypted private part
}

// AddressPrivate is the private/encrypted part of a nymaddress.
type AddressPrivate struct {
	System         int32  // The system number. should be 0
	Address        []byte // The final address to deliver to
	Expire         int64  // The time when the address should not be used anymore
	SingleUse      bool   // If the address may be used more than once
	MinDelay       int32  // Minimum delay in the mix
	MaxDelay       int32  // Maximum delay in the mix
	Nonce          []byte // Random data, size KeySize
	ReceiverPubKey []byte // The pubkey of the receiver
	EncNym         []byte // The encrypted Nym
	HMACHead       []byte // The HMAC of the header (nonce, receiverpubkey, encnym)
}

// RelayHeader is the header of a relayed (post-mix) message.
type RelayHeader struct {
	SenderKey      []byte // Pubkey of the sender (mix), per message
	Nonce          []byte // Random data, size KeySize
	ReceiverPubKey []byte // The pubkey of the receiver
	EncNym         []byte // The encrypted Nym
	HMACHead       []byte // The HMAC of the header (nonce, receiverpubkey, encnym)
}

// AddressTemplate contains parameters for address creation.
type AddressTemplate struct {
	Secret []byte // The local secret for address creation, must be random and long-lived

	System        int32               // The system number. should be 0
	MixCandidates mixaddr.AddressList // A list of mixes

	Expire    int64 // The time when the address should not be used anymore
	SingleUse bool  // If the address may be used more than once
	MinDelay  int32 // Minimum delay in the mix
	MaxDelay  int32 // Maximum delay in the mix
}

func genKeyRandom() (pub, priv *[KeySize]byte, err error) {
	privateKey, err := genNonce()
	if err != nil {
		return nil, nil, err
	}
	publicKey := new([KeySize]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return publicKey, privateKey, nil
}

func genNonce() (nonce *[KeySize]byte, err error) {
	nonce = new([KeySize]byte)
	if _, err = io.ReadFull(Rand, nonce[:]); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ParseAddress parses an address.
func ParseAddress(address []byte) (*Address, error) {
	a := new(Address)
	_, err := asn1.Unmarshal(address, a)
	if err != nil {
		return nil, err
	}
	if a.Expire < times.Now() {
		return nil, ErrExpired
	}
	return a, nil
}

// GetMixData decrypts the private portion of a nymaddress.
func (ad *Address) GetMixData(keysLookup KeyFunc) (*AddressPrivate, error) {
	pubkey := new([KeySize]byte)
	copy(pubkey[:], ad.MixPubKey)
	privkey := keysLookup(pubkey)
	if privkey == nil {
		return nil, ErrNoKey
	}
	sharedSecret := new([KeySize]byte)
	addrKey := new([KeySize]byte)
	copy(addrKey[:], ad.AddressKey)
	curve25519.ScalarMult(sharedSecret, privkey, addrKey)
	cr, err := lioness.New(sharedSecret[:]) // saves some bytes and is safe against tagging
	if err != nil {
		return nil, err
	}
	privmarshal, err := cr.Decrypt(ad.PrivateData)
	if err != nil {
		return nil, err
	}
	ap := new(AddressPrivate)
	_, err = asn1.Unmarshal(privmarshal, ap)
	if err != nil {
		return nil, err
	}
	return ap, nil
}

// GetUnique returns a unique value of the nymaddress IF the nymaddress is
// single use, nil otherwise.
func (ap AddressPrivate) GetUnique() []byte {
	if ap.SingleUse {
		return ap.ReceiverPubKey
	}
	return nil
}

// GetHeader returns the header for a relay message and a secret for encryption.
func (ap AddressPrivate) GetHeader() (header, secret []byte, err error) {
	pubkey, privkey, err := genKeyRandom()
	if err != nil {
		return nil, nil, err
	}
	rh := RelayHeader{
		SenderKey:      pubkey[:],
		Nonce:          ap.Nonce,
		ReceiverPubKey: ap.ReceiverPubKey,
		EncNym:         ap.EncNym,
		HMACHead:       ap.HMACHead,
	}
	d, err := asn1.Marshal(rh)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret := new([KeySize]byte)
	receiverPubKey := new([KeySize]byte)
	copy(receiverPubKey[:], ap.ReceiverPubKey)
	curve25519.ScalarMult(sharedSecret, privkey, receiverPubKey)
	return d, sharedSecret[:], nil
}

// GetPrivate gets the shared secret from a header.
func (tmp AddressTemplate) GetPrivate(header, MailboxAddress []byte) (nym, secret []byte, err error) {
	rh := new(RelayHeader)
	_, err = asn1.Unmarshal(header, rh)
	if err != nil {
		return nil, nil, err
	}
	symkey := tmp.genSymKey(rh.Nonce, rh.ReceiverPubKey, MailboxAddress)
	HMACHead := calcHmac(symkey, rh.Nonce, rh.ReceiverPubKey, rh.EncNym)
	if !hmac.Equal(rh.HMACHead, HMACHead) {
		return nil, nil, ErrHMAC
	}
	nym = decryptNym(symkey, rh.EncNym)
	recPub, recPriv := tmp.genDetermKeys(rh.Nonce, nym)
	if !bytes.Equal(recPub[:], rh.ReceiverPubKey) {
		return nil, nil, ErrBadKey
	}
	sharedSecret := new([KeySize]byte)
	senderPubKey := new([KeySize]byte)
	copy(senderPubKey[:], rh.SenderKey)
	curve25519.ScalarMult(sharedSecret, recPriv, senderPubKey)
	return nym, sharedSecret[:], nil
}

// NewAddress generates a new nymaddress for nym/address from AddressTemplate.
// Only the first KeySize bytes of Nym are used, so use a hash of the true nym
// here.
func (tmp AddressTemplate) NewAddress(MailboxAddress, Nym []byte) ([]byte, error) {
	xnym := make([]byte, KeySize)
	copy(xnym, Nym)
	Nym = xnym
	mixAddress := tmp.MixCandidates.Expire(tmp.Expire).Rand() // Select a random mix
	if mixAddress == nil {
		return nil, ErrNoMix
	}
	pubKeyRand, privKeyRand, err := genKeyRandom()
	if err != nil {
		return nil, err
	}
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}

	nymaddr := new(Address)
	nymaddr.MixAddress = []byte(mixAddress.Address)
	nymaddr.MixPubKey = mixAddress.Pubkey
	nymaddr.TokenPubKey = mixAddress.TokenKey
	nymaddr.Expire = tmp.Expire
	nymaddr.SingleUse = tmp.SingleUse
	nymaddr.AddressKey = pubKeyRand[:]

	nymprivate := new(AddressPrivate)
	nymprivate.System = tmp.System
	nymprivate.Expire = tmp.Expire
	nymprivate.Address = MailboxAddress
	nymprivate.SingleUse = tmp.SingleUse
	nymprivate.MinDelay = tmp.MinDelay
	nymprivate.MaxDelay = tmp.MaxDelay
	nymprivate.Nonce = nonce[:]

	// Calculate public key that the mix will encrypt TO
	recPub, _ := tmp.genDetermKeys(nymprivate.Nonce, Nym)
	nymprivate.ReceiverPubKey = recPub[:]

	// Calculate symmetric key
	symkey := tmp.genSymKey(nymprivate.Nonce, nymprivate.ReceiverPubKey, nymprivate.Address)

	nymprivate.EncNym = encryptNym(symkey, Nym)

	nymprivate.HMACHead = calcHmac(symkey, nymprivate.Nonce, nymprivate.ReceiverPubKey, nymprivate.EncNym)

	privmarshal, err := asn1.Marshal(*nymprivate)
	if err != nil {
		return nil, err
	}
	mixPubKey := new([KeySize]byte)
	sharedSecret := new([KeySize]byte)
	copy(mixPubKey[:], nymaddr.MixPubKey)
	curve25519.ScalarMult(sharedSecret, privKeyRand, mixPubKey)
	cr, err := lioness.New(sharedSecret[:]) // saves some bytes and is safe against tagging
	if err != nil {
		return nil, err
	}
	privmarshalEnc, err := cr.Encrypt(privmarshal)
	if err != nil {
		return nil, err
	}
	nymaddr.PrivateData = privmarshalEnc
	return asn1.Marshal(*nymaddr)
}

func calcHmac(key []byte, data ...[]byte) []byte {
	h := hmac.New(crypto.SHA256.New, key)
	for _, e := range data {
		h.Write(e)
	}
	x := h.Sum(make([]byte, 0))
	return x[:]
}

func (tmp AddressTemplate) genDetermKeys(nonce, nym []byte) (pub, priv *[KeySize]byte) {
	pub, priv = new([KeySize]byte), new([KeySize]byte)
	privkeyA := calcHmac(tmp.Secret, nonce, nym)
	copy(priv[:], privkeyA)
	curve25519.ScalarBaseMult(pub, priv)
	return pub, priv
}

func (tmp AddressTemplate) genSymKey(nonce, receiverpubkey, deliveryaddress []byte) []byte {
	return calcHmac(tmp.Secret, nonce, receiverpubkey, deliveryaddress)
}
