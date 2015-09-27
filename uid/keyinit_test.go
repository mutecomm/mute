// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uid

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/util/times"
)

func TestKeyInitSuccess(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// success
	ki, _, _, err := msg.KeyInit(1, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// getter methods
	if ki.MsgCount() != ki.CONTENTS.MSGCOUNT {
		t.Error("msgCount mismatch")
	}
	if ki.SigKeyHash() != ki.CONTENTS.SIGKEYHASH {
		t.Error("sigKeyHash mismatch")
	}
	// JSON conversion
	jsn := ki.JSON()
	jsnKI, err := NewJSONKeyInit(jsn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsn, jsnKI.JSON()) {
		t.Errorf("KeyInits differ")
	}
	// verify
	uris := make([]string, 1)
	uris[0] = "mute.berlin"
	if err := ki.Verify(uris, msg.UIDContent.SIGKEY.PUBKEY); err != nil {
		t.Error(err)
	}
	// sign
	sigKey, err := cipher.Ed25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ki.Sign(sigKey)
	// verify signature
	pubKey := base64.Encode(sigKey.PublicKey()[:])
	if err := ki.VerifySrvSig(sig, pubKey); err != nil {
		t.Error(err)
	}
}

func TestExpired(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// success
	ki, _, _, err := msg.KeyInit(1, uint64(times.Now()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// wait until key init expires
	time.Sleep(time.Second)
	// verify
	uris := make([]string, 1)
	uris[0] = "mute.berlin"
	if err := ki.Verify(uris, msg.UIDContent.SIGKEY.PUBKEY); err != ErrExpired {
		t.Error("should fail")
	}
}

func TestKeyInitFailure(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// invalid times
	_, _, _, err = msg.KeyInit(0, 0, 0, false, "mute.berlin", "", "",
		cipher.RandReader)
	if err != ErrInvalidTimes {
		t.Error("should fail")
	}
	_, _, _, err = msg.KeyInit(0, 1, 0, false, "mute.berlin", "", "",
		cipher.RandReader)
	if err != ErrExpired {
		t.Error("should fail")
	}
	_, _, _, err = msg.KeyInit(0, uint64(times.OneYearLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != ErrFuture {
		t.Fatal(err)
	}
	// rand fail
	_, _, _, err = msg.KeyInit(0, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandFail)
	if err == nil {
		t.Error("should fail")
	}
	// decode failure
	msg.UIDContent.SIGKEY.HASH = "!"
	_, _, _, err = msg.KeyInit(0, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err == nil {
		t.Error("should fail")
	}
}

func TestVerifyFailure(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Create("other@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// success
	ki, _, _, err := msg.KeyInit(1, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	ki2, _, _, err := other.KeyInit(0, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// repo URI
	if err := ki.Verify(nil, msg.UIDContent.SIGKEY.PUBKEY); err != ErrRepoURI {
		t.Error("should fail")
	}
	// sighash
	uris := make([]string, 1)
	uris[0] = "mute.berlin"
	if err := ki.Verify(uris, other.UIDContent.SIGKEY.PUBKEY); err != ErrWrongSigKeyHash {
		t.Error("should fail")
	}
	// bad signature
	sig := ki.SIGNATURE
	ki.SIGNATURE = "!"
	if err := ki.Verify(uris, msg.UIDContent.SIGKEY.PUBKEY); err == nil {
		t.Error("should fail")
	}
	ki.SIGNATURE = sig
	pubKey := msg.UIDContent.SIGKEY.PUBKEY
	msg.UIDContent.SIGKEY.PUBKEY = "!"
	if err := ki.Verify(uris, msg.UIDContent.SIGKEY.PUBKEY); err == nil {
		t.Error("should fail")
	}
	// wrong signature
	msg.UIDContent.SIGKEY.PUBKEY = pubKey
	ki.SIGNATURE = ki2.SIGNATURE
	if err := ki.Verify(uris, msg.UIDContent.SIGKEY.PUBKEY); err != ErrInvalidKeyInitSig {
		t.Error("should fail")
	}
	// invalid times
	ki2.CONTENTS.MSGCOUNT = 1
	ki2.CONTENTS.NOTAFTER = 0
	if err := ki2.Verify(uris, other.UIDContent.SIGKEY.PUBKEY); err != ErrInvalidTimes {
		t.Error("should fail")
	}
}

func TestVerifySrvSigfailure(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// success
	ki, _, _, err := msg.KeyInit(1, uint64(times.NinetyDaysLater()), 0, false,
		"mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// sign
	sigKey, err := cipher.Ed25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ki.Sign(sigKey)
	pubKey := base64.Encode(sigKey.PublicKey()[:])
	// invalid signature
	if err := ki.VerifySrvSig("!", pubKey); err == nil {
		t.Error("should fail")
	}
	// invalid public key
	if err := ki.VerifySrvSig(sig, "!"); err == nil {
		t.Error("should fail")
	}
	// invalid signature
	var signature [ed25519.PrivateKeySize]byte
	if _, err := io.ReadFull(cipher.RandReader, signature[:]); err != nil {
		t.Fatal(err)
	}
	sig = base64.Encode(signature[:])
	if err := ki.VerifySrvSig(sig, pubKey); err == nil {
		t.Error("should fail")
	}
}

func TestSessionAnchor(t *testing.T) {
	// create UID message
	msg, err := Create("alice@mute.berlin", false, "", "", Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	// KeyInit
	now := uint64(times.Now())
	ki, _, privKey, err := msg.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}

	// SesionAnchor
	sa, err := ki.SessionAnchor(msg.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}

	// check private key methods
	if err := sa.SetPrivateKey(privKey); err != nil {
		t.Fatal(err)
	}
	if privKey != sa.PrivateKey() {
		t.Fatal("private keys differ")
	}
}
