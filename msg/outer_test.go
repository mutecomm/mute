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
	"testing"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/times"
)

func TestPreHeaderSize(t *testing.T) {
	t.Parallel()
	senderHeaderKey, err := cipher.Curve25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	ph := newPreHeader(senderHeaderKey.PublicKey()[:])
	var buf bytes.Buffer
	if err := ph.write(&buf); err != nil {
		t.Fatal(err)
	}
	oh := newOuterHeader(preHeaderPacket, 0, buf.Bytes())
	if oh.size() != preHeaderSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), preHeaderSize)
	}
}

func TestEncrypteHeaderSizeAndPadding(t *testing.T) {
	t.Parallel()
	// setup UIDs and stuff
	aliceUID, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	aliceKI, _, _, err := aliceUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	aliceKE, err := aliceKI.KeyEntryECDHE25519(aliceUID.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	bobUID, err := uid.Create("bob@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bobKI, _, _, err := bobUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bobKE, err := bobKI.KeyEntryECDHE25519(bobUID.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}

	// create unencrypted header
	h, err := newHeader(aliceUID, bobUID, bobKE.HASH, aliceKE, nil, nil,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	// create sender key
	senderHeaderKey, err := cipher.Curve25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	// create (encrypted) header packet
	recipientIdentityPub, err := bobUID.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	hp, err := newHeaderPacket(h, recipientIdentityPub,
		senderHeaderKey.PrivateKey(), cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	// write (encrypted) header packet
	var buf bytes.Buffer
	if err := hp.write(&buf); err != nil {
		t.Fatal(err)
	}
	oh := newOuterHeader(encryptedHeader, 1, buf.Bytes())
	if oh.size() != encryptedHeaderSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), encryptedHeaderSize)
	}
}

func TestCryptoSetupSize(t *testing.T) {
	t.Parallel()
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cipher.RandReader, iv); err != nil {
		t.Fatal(err)
	}
	oh := newOuterHeader(cryptoSetup, 2, iv)
	if oh.size() != cryptoSetupSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), cryptoSetupSize)
	}
}

func TestEncryptedPacketSize(t *testing.T) {
	t.Parallel()
	ih := newInnerHeader(dataType, false, nil)
	var buf bytes.Buffer
	if err := ih.write(&buf); err != nil {
		t.Fatal(err)
	}
	oh := newOuterHeader(encryptedPacket, 3, buf.Bytes())
	if oh.size() != encryptedPacketSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), encryptedPacketSize)
	}
}

func TestSignatureSize(t *testing.T) {
	t.Parallel()
	_, privKey, err := ed25519.GenerateKey(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(privKey, cipher.SHA512([]byte("test")))
	ih := newInnerHeader(signatureType, false, sig[:])
	var buf bytes.Buffer
	if err := ih.write(&buf); err != nil {
		t.Fatal(err)
	}
	oh := newOuterHeader(encryptedPacket, 4, buf.Bytes())
	if oh.size() != signatureSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), signatureSize)
	}
}

func TestHMACSize(t *testing.T) {
	t.Parallel()
	oh := newOuterHeader(hmacPacket, 5, nil)
	oh.PLen = sha512.Size
	hmacKey := make([]byte, 64)
	if _, err := io.ReadFull(cipher.RandReader, hmacKey); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha512.New, hmacKey)
	oh.inner = mac.Sum(oh.inner)
	if oh.size() != hmacSize {
		t.Errorf("oh.size() = %d != %d", oh.size(), hmacSize)
	}
}
