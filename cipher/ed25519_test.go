// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"testing"
)

func TestEd25519(t *testing.T) {
	if _, err := Ed25519Generate(RandFail); err == nil {
		t.Error("should fail")
	}
	e, err := Ed25519Generate(RandReader)
	if err != nil {
		t.Error(err)
	}
	msg := []byte("message")
	pubKey := e.PublicKey()
	privKey := e.PrivateKey()
	sig := e.Sign(msg)
	if err := e.SetPublicKey(msg); err == nil {
		t.Error("should fail")
	}
	if err := e.SetPublicKey(pubKey[:]); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPrivateKey(msg); err == nil {
		t.Error("should fail")
	}
	if err := e.SetPrivateKey(privKey[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubKey[:], e.PublicKey()[:]) {
		t.Errorf("public keys differ")
	}
	if !bytes.Equal(privKey[:], e.PrivateKey()[:]) {
		t.Errorf("private keys differ")
	}
	if !e.Verify(msg, sig) {
		t.Error("verify failed")
	}
}
