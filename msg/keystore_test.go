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
	// encrypt message from Alice to Bob
	var encMsg bytes.Buffer
	aliceKeyStore := memstore.New()
	encryptArgs := &msg.EncryptArgs{
		Writer:                 &encMsg,
		From:                   aliceUID,
		To:                     bobUID,
		RecipientTemp:          bobKE,
		SenderLastKeychainHash: hashchain.TestEntry,
		Reader:                 bytes.NewBufferString(msgs.Message1),
		Rand:                   cipher.RandReader,
		KeyStore:               aliceKeyStore,
	}
	err = msg.Encrypt(encryptArgs)
	if err != nil {
		t.Fatal(err)
	}
	// make sure sender key has been deleted
	if _, err := aliceKeyStore.GetMessageKey(alice, bob, true, 0); err == nil {
		t.Error("should fail")
	}
	// decrypt message from Alice to Bob
	var res bytes.Buffer
	identities := []string{bobUID.Identity()}
	recipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
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
	bobKeyStore.AddKeyEntry(bobKE)
	decryptArgs := &msg.DecryptArgs{
		Writer:              &res,
		Identities:          identities,
		RecipientIdentities: recipientIdentities,
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
}
