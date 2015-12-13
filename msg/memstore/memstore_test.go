// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package memstore

import (
	"bytes"
	"io"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/times"
)

func TestKeyEntry(t *testing.T) {
	ms := New()
	uidMsg, err := uid.Create("alice@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(times.Now())
	ki, _, _, err := uidMsg.KeyInit(1, now+times.Day, now-times.Day, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	ke, err := ki.KeyEntryECDHE25519(uidMsg.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	// private
	ms.AddPrivateKeyEntry(ke)
	entry, err := ms.GetPrivateKeyEntry(ke.HASH)
	if err != nil {
		t.Error(err)
	} else if entry != ke {
		t.Error("entry != ke")
	}
	if _, err := ms.GetPrivateKeyEntry("MUTE"); err == nil {
		t.Error("should fail")
	}
	// public
	ms.AddPublicKeyEntry(uidMsg.Identity(), ke)
	entry, err = ms.GetPublicKeyEntry(uidMsg)
	if err != nil {
		t.Error(err)
	} else if entry != ke {
		t.Error("entry != ke")
	}
	uidMsg, err = uid.Create("trent@mute.berlin", false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.GetPublicKeyEntry(uidMsg); err != msg.ErrNoKeyInit {
		t.Error("should fail with msg.ErrNoKeyInit")
	}
}

func genMessageKey() (*[64]byte, error) {
	var messageKey [64]byte
	if _, err := io.ReadFull(cipher.RandReader, messageKey[:]); err != nil {
		return nil, err
	}
	return &messageKey, nil
}

func TestSessenStore(t *testing.T) {
	ms := New()
	sendKey, err := genMessageKey()
	if err != nil {
		t.Fatal(err)
	}
	recvKey, err := genMessageKey()
	if err != nil {
		t.Fatal(err)
	}
	err = ms.StoreSession("alice@mute.berlin", "bob@mute.berlin",
		base64.Encode(cipher.SHA512([]byte("rootkey"))),
		base64.Encode(cipher.SHA512([]byte("chainkey"))),
		[]string{base64.Encode(sendKey[:])},
		[]string{base64.Encode(recvKey[:])})
	if err != nil {
		t.Fatal(err)
	}
	// test sender key
	key, err := ms.GetMessageKey("alice@mute.berlin", "bob@mute.berlin", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], sendKey[:]) {
		t.Error("send key differs")
	}
	err = ms.DelMessageKey("alice@mute.berlin", "bob@mute.berlin", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ms.GetMessageKey("alice@mute.berlin", "bob@mute.berlin", true, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}
	// test receiver key
	key, err = ms.GetMessageKey("alice@mute.berlin", "bob@mute.berlin", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], recvKey[:]) {
		t.Error("recv key differs")
	}
	err = ms.DelMessageKey("alice@mute.berlin", "bob@mute.berlin", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ms.GetMessageKey("alice@mute.berlin", "bob@mute.berlin", false, 0)
	if err != msg.ErrMessageKeyUsed {
		t.Error("should fail with msg.ErrMessageKeyUsed")
	}
}

func TestSessionState(t *testing.T) {
	ms := New()
	ss := &msg.SessionState{
		SenderSessionCount:    1,
		SenderMessageCount:    2,
		RecipientSessionCount: 3,
		RecipientMessageCount: 4,
	}
	err := ms.SetSessionState("alice@mute.berlin", "bob@mute.berlin", ss)
	if err != nil {
		t.Fatal(err)
	}
	sss, err := ms.GetSessionState("alice@mute.berlin", "bob@mute.berlin")
	if err != nil {
		t.Fatal(err)
	}
	if ss != sss {
		t.Error("session states differ")
	}
}
