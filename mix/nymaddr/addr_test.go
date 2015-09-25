package nymaddr

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/mutecomm/mute/mix/mixaddr"
	"github.com/mutecomm/mute/util/times"
)

var pubkey = []byte{0x59, 0x69, 0x2c, 0xf9, 0xb7, 0x1f, 0x88, 0x49, 0x10, 0x46, 0xa4, 0xe7, 0x7d, 0x2d, 0x84, 0xb7, 0xf7, 0xd1, 0x89, 0x4a, 0x09, 0x2f, 0x56, 0xfe, 0x2f, 0x00, 0x03, 0xf2, 0xba, 0x26, 0x9f, 0x1f}
var privkey = []byte{0x59, 0xb6, 0x8b, 0x32, 0x09, 0xbf, 0x5a, 0x0a, 0x7d, 0x72, 0xc3, 0x9f, 0x3f, 0x4b, 0xe0, 0x9d, 0x16, 0xaf, 0x38, 0x6a, 0x75, 0x2b, 0x4f, 0x93, 0xe3, 0x8a, 0xa7, 0xe0, 0x77, 0x59, 0x3f, 0x3f}

var testTemplate = AddressTemplate{
	Secret: []byte("local nym secret"),
	System: 0,

	MixCandidates: append(make(mixaddr.AddressList, 0),
		mixaddr.Address{
			Pubkey:  pubkey,
			Expire:  int64(^uint64(0) >> 1),
			Address: "mix1@mute.berlin",
		},
	),

	Expire:    times.Now() + 100,
	SingleUse: false,
	MinDelay:  10,
	MaxDelay:  30,
}

func TestNewAddr(t *testing.T) {
	var pkey, pubk [KeySize]byte
	mailbox := []byte("mailbox")
	nymIn := []byte("Nym45678901234567890123456789012")
	copy(pkey[:], privkey)
	copy(pubk[:], pubkey)

	nymaddr, err := testTemplate.NewAddress(mailbox, nymIn)
	if err != nil {
		t.Fatalf("NymAddr.NewAddress failed: %s", err)
	}
	addr, err := ParseAddress(nymaddr)
	if err != nil {
		t.Fatalf("NymAddr.ParseAddress failed: %s", err)
	}
	priv, err := addr.GetMixData(func(*[KeySize]byte) *[KeySize]byte {
		return &pkey
	})
	if err != nil {
		t.Fatalf("NymAddr.GetPrivate failed: %s", err)
	}
	header, secret, err := priv.GetHeader()
	if err != nil {
		t.Fatalf("NymAddr.GetHeader failed: %s", err)
	}
	nym2, secret2, err := testTemplate.GetPrivate(header, mailbox)
	if err != nil {
		t.Fatalf("Header/Template.GetPrivate failed: %s", err)
	}
	if !bytes.Equal(secret, secret2) {
		t.Error("Mix/Receiver mismatched secrets")
	}
	if !bytes.Equal(nymIn, nym2) {
		t.Error("Nym Decode failed")
	}
}

func TestNymEncrypt(t *testing.T) {
	nym := []byte("TestNym")
	key := sha256.Sum256([]byte("TestKey"))
	encnym := encryptNym(key[:], nym)
	nym2 := decryptNym(key[:], encnym)
	if string(nym2) != string(nym) {
		t.Fatal("enc/decrypt fail")
	}
}
