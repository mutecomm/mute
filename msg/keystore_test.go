// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg_test

import (
	"bytes"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/msg/memstore"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/msgs"
	"github.com/mutecomm/mute/util/times"
)

func TestKeyStore(t *testing.T) {
	alice := "alice@mute.berlin"
	aliceUID, err := uid.Create(alice, false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bob := "bob@mute.berlin"
	bobUID, err := uid.Create(bob, false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	bobKI, _, privateKey, err := bobUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bobKE, err := bobKI.KeyEntryECDHE25519(bobUID.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	// encrypt first message from Alice to Bob
	var encMsg bytes.Buffer
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	encryptArgs := &msg.EncryptArgs{
		Writer: &encMsg,
		From:   aliceUID,
		To:     bobUID,
		SenderLastKeychainHash: hashchain.TestEntry,
		Reader:                 bytes.NewBufferString(msgs.Message1),
		Rand:                   cipher.RandReader,
		KeyStore:               aliceKeyStore,
	}
	if _, err = msg.Encrypt(encryptArgs); err != nil {
		t.Fatal(err)
	}
	// make sure sender key has been deleted
	_, err = aliceKeyStore.GetMessageKey(alice, bob, true, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}
	// decrypt first message from Alice to Bob
	var res bytes.Buffer
	bobIdentities := []string{bobUID.Identity()}
	bobRecipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
	input := base64.NewDecoder(&encMsg)
	version, preHeader, err := msg.ReadFirstOuterHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	if version != msg.Version {
		t.Fatal("wrong version")
	}
	bobKeyStore := memstore.New()
	if err := bobKE.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)
	decryptArgs := &msg.DecryptArgs{
		Writer:              &res,
		Identities:          bobIdentities,
		RecipientIdentities: bobRecipientIdentities,
		PreviousRootKeyHash: nil,
		PreHeader:           preHeader,
		Reader:              input,
		KeyStore:            bobKeyStore,
	}
	_, _, err = msg.Decrypt(decryptArgs)
	if err != nil {
		t.Fatal(err)
	}
	if res.String() != msgs.Message1 {
		t.Fatal("messages differ")
	}
	// make recipient key has been deleted
	_, err = bobKeyStore.GetMessageKey(bob, alice, false, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}

	// encrypt first reply from Bob to Alice
	encMsg.Reset()
	encryptArgs = &msg.EncryptArgs{
		Writer: &encMsg,
		From:   bobUID,
		To:     aliceUID,
		SenderLastKeychainHash: hashchain.TestEntry,
		Reader:                 bytes.NewBufferString(msgs.Message2),
		Rand:                   cipher.RandReader,
		KeyStore:               bobKeyStore,
	}
	if _, err = msg.Encrypt(encryptArgs); err != nil {
		t.Fatal(err)
	}
	// make sure sender key has been deleted
	_, err = bobKeyStore.GetMessageKey(bob, alice, true, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}

	// decrypt first reply from Bob to Alice
	res.Reset()
	aliceIdentities := []string{aliceUID.Identity()}
	aliceRecipientIdentities := []*uid.KeyEntry{aliceUID.PubKey()}
	input = base64.NewDecoder(&encMsg)
	version, preHeader, err = msg.ReadFirstOuterHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	if version != msg.Version {
		t.Fatal("wrong version")
	}
	decryptArgs = &msg.DecryptArgs{
		Writer:              &res,
		Identities:          aliceIdentities,
		RecipientIdentities: aliceRecipientIdentities,
		PreviousRootKeyHash: nil,
		PreHeader:           preHeader,
		Reader:              input,
		KeyStore:            aliceKeyStore,
	}
	_, _, err = msg.Decrypt(decryptArgs)
	if err != nil {
		t.Fatal(err)
	}
	if res.String() != msgs.Message2 {
		t.Fatal("messages differ")
	}
	// make recipient key has been deleted
	_, err = aliceKeyStore.GetMessageKey(alice, bob, false, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}
}
