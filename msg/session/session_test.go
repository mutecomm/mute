// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session_test

import (
	"bytes"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/msg/session/memstore"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/msgs"
	"github.com/mutecomm/mute/util/times"
)

func init() {
	if err := log.Init("info", "msg  ", "", true); err != nil {
		panic(err)
	}
}

func TestKeyStore(t *testing.T) {
	defer log.Flush()
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
	log.Info("### encrypt first message from Alice to Bob")
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
	aliceHash := aliceKeyStore.SenderSessionPubHash()
	_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, true, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}
	// decrypt first message from Alice to Bob
	log.Info("### decrypt first message from Alice to Bob")
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
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
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
	bobHash := bobKeyStore.SenderSessionPubHash()
	_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, false, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// encrypt first reply from Bob to Alice
	log.Info("### encrypt first reply from Bob to Alice")
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
	_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, true, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// decrypt first reply from Bob to Alice
	log.Info("### decrypt first reply from Bob to Alice")
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
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
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
	_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, false, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// encrypt second message from Alice to Bob
	log.Info("### encrypt second message from Alice to Bob")
	encMsg.Reset()
	encryptArgs = &msg.EncryptArgs{
		Writer: &encMsg,
		From:   aliceUID,
		To:     bobUID,
		SenderLastKeychainHash: hashchain.TestEntry,
		Reader:                 bytes.NewBufferString(msgs.Message3),
		Rand:                   cipher.RandReader,
		KeyStore:               aliceKeyStore,
	}
	if _, err = msg.Encrypt(encryptArgs); err != nil {
		t.Fatal(err)
	}
	// make sure sender key has been deleted
	aliceHash = aliceKeyStore.SenderSessionPubHash()
	_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, true, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// decrypt second message from Alice to Bob
	log.Info("### decrypt second message from Alice to Bob")
	res.Reset()
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
		Identities:          bobIdentities,
		RecipientIdentities: bobRecipientIdentities,
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
		KeyStore:            bobKeyStore,
	}
	_, _, err = msg.Decrypt(decryptArgs)
	if err != nil {
		t.Fatal(err)
	}
	if res.String() != msgs.Message3 {
		t.Fatal("messages differ")
	}
	// make recipient key has been deleted
	bobHash = bobKeyStore.SenderSessionPubHash()
	_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, false, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// encrypt second reply from Bob to Alice
	log.Info("### encrypt second reply from Bob to Alice")
	encMsg.Reset()
	encryptArgs = &msg.EncryptArgs{
		Writer: &encMsg,
		From:   bobUID,
		To:     aliceUID,
		SenderLastKeychainHash: hashchain.TestEntry,
		Reader:                 bytes.NewBufferString(msgs.Message4),
		Rand:                   cipher.RandReader,
		KeyStore:               bobKeyStore,
	}
	if _, err = msg.Encrypt(encryptArgs); err != nil {
		t.Fatal(err)
	}
	// make sure sender key has been deleted
	_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, true, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}

	// decrypt second reply from Bob to Alice
	log.Info("### decrypt second reply from Bob to Alice")
	res.Reset()
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
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
		KeyStore:            aliceKeyStore,
	}
	_, _, err = msg.Decrypt(decryptArgs)
	if err != nil {
		t.Fatal(err)
	}
	if res.String() != msgs.Message4 {
		t.Fatal("messages differ")
	}
	// make recipient key has been deleted
	_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, false, 0)
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}
}

func TestExhaustSessionSequential(t *testing.T) {
	defer log.Flush()
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
	// encrypt messages from Alice to Bob
	var encMsgs []*bytes.Buffer
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	for i := 0; i < 2*msg.NumOfFutureKeys+1; i++ {
		var encMsg bytes.Buffer
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
		aliceHash := aliceKeyStore.SenderSessionPubHash()
		_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, true, uint64(i))
		if err != session.ErrMessageKeyUsed {
			t.Error("should fail with session.ErrMessageKeyUsed")
		}
		encMsgs = append(encMsgs, &encMsg)
	}
	bobIdentities := []string{bobUID.Identity()}
	bobRecipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
	bobKeyStore := memstore.New()
	if err := bobKE.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)
	for i := 0; i < 2*msg.NumOfFutureKeys+1; i++ {
		// decrypt messages from Alice to Bob
		var res bytes.Buffer
		input := base64.NewDecoder(encMsgs[i])
		version, preHeader, err := msg.ReadFirstOuterHeader(input)
		if err != nil {
			t.Fatal(err)
		}
		if version != msg.Version {
			t.Fatal("wrong version")
		}
		decryptArgs := &msg.DecryptArgs{
			Writer:              &res,
			Identities:          bobIdentities,
			RecipientIdentities: bobRecipientIdentities,
			PreHeader:           preHeader,
			Reader:              input,
			Rand:                cipher.RandReader,
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
		bobHash := bobKeyStore.SenderSessionPubHash()
		_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, false, uint64(i))
		if err != session.ErrMessageKeyUsed {
			t.Error("should fail with session.ErrMessageKeyUsed")
		}
	}
}

func TestExhaustSessionLast(t *testing.T) {
	defer log.Flush()
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
	// encrypt messages from Alice to Bob
	var encMsgs []*bytes.Buffer
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	for i := 0; i < 2*msg.NumOfFutureKeys+1; i++ {
		var encMsg bytes.Buffer
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
		aliceHash := aliceKeyStore.SenderSessionPubHash()
		_, err = aliceKeyStore.GetMessageKey(alice, bob, aliceHash, true, uint64(i))
		if err != session.ErrMessageKeyUsed {
			t.Error("should fail with session.ErrMessageKeyUsed")
		}
		encMsgs = append(encMsgs, &encMsg)
	}
	bobIdentities := []string{bobUID.Identity()}
	bobRecipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
	bobKeyStore := memstore.New()
	if err := bobKE.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)
	// decrypt last message from Alice to Bob
	log.Debug("### decrypt last message from Alice to Bob")
	var res bytes.Buffer
	input := base64.NewDecoder(encMsgs[2*msg.NumOfFutureKeys])
	version, preHeader, err := msg.ReadFirstOuterHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	if version != msg.Version {
		t.Fatal("wrong version")
	}
	decryptArgs := &msg.DecryptArgs{
		Writer:              &res,
		Identities:          bobIdentities,
		RecipientIdentities: bobRecipientIdentities,
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
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
	bobHash := bobKeyStore.SenderSessionPubHash()
	_, err = bobKeyStore.GetMessageKey(bob, alice, bobHash, false,
		uint64(2*msg.NumOfFutureKeys))
	if err != session.ErrMessageKeyUsed {
		t.Error("should fail with session.ErrMessageKeyUsed")
	}
}

func TestSimultaneousSessions(t *testing.T) {
	defer log.Flush()
	alice := "alice@mute.berlin"
	aliceUID, err := uid.Create(alice, false, "", "", uid.Strict,
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
	bob := "bob@mute.berlin"
	bobUID, err := uid.Create(bob, false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bobKI, _, bobPrivateKey, err := bobUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	bobKE, err := bobKI.KeyEntryECDHE25519(bobUID.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	// encrypt first message from Alice to Bob
	var aliceEncMsg bytes.Buffer
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	encryptArgs := &msg.EncryptArgs{
		Writer: &aliceEncMsg,
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
	// encrypt first message from Bob to Alice (simultaneously)
	var bobEncMsg bytes.Buffer
	bobKeyStore := memstore.New()
	bobKeyStore.AddPublicKeyEntry(alice, aliceKE)
	encryptArgs = &msg.EncryptArgs{
		Writer: &bobEncMsg,
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
	// decrypt first message from Alice to Bob
	var res bytes.Buffer
	bobIdentities := []string{bobUID.Identity()}
	bobRecipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
	input := base64.NewDecoder(&aliceEncMsg)
	version, preHeader, err := msg.ReadFirstOuterHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	if version != msg.Version {
		t.Fatal("wrong version")
	}
	if err := bobKE.SetPrivateKey(bobPrivateKey); err != nil {
		t.Fatal(err)
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)
	decryptArgs := &msg.DecryptArgs{
		Writer:              &res,
		Identities:          bobIdentities,
		RecipientIdentities: bobRecipientIdentities,
		PreHeader:           preHeader,
		Reader:              input,
		Rand:                cipher.RandReader,
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
