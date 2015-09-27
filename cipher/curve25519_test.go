// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"testing"
)

func TestCurve25519(t *testing.T) {
	if _, err := Curve25519Generate(RandFail); err == nil {
		t.Error("should fail")
	}
	c, err := Curve25519Generate(RandReader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := c.PublicKey()
	privKey := c.PrivateKey()
	if err := c.SetPublicKey(pubKey[:]); err != nil {
		t.Error(err)
	}
	if err := c.SetPublicKey(nil); err == nil {
		t.Error("should fail")
	}
	if err := c.SetPrivateKey(privKey[:]); err != nil {
		t.Error(err)
	}
	if err := c.SetPrivateKey(nil); err == nil {
		t.Error("should fail")
	}
	if !bytes.Equal(pubKey[:], c.PublicKey()[:]) {
		t.Error("public keys differ")
	}
	if !bytes.Equal(privKey[:], c.PrivateKey()[:]) {
		t.Error("private keys differ")
	}
}

func TestECDH(t *testing.T) {
	s, err := Curve25519Generate(RandReader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Curve25519Generate(RandReader)
	if err != nil {
		t.Fatal(err)
	}
	secretA, err := ECDH(s.PrivateKey(), r.PublicKey(), s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	secretB, err := ECDH(r.PrivateKey(), s.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secretA[:], secretB[:]) {
		t.Error("shared secrets differ")
	}
	if _, err := ECDH(nil, r.PublicKey(), nil); err == nil {
		t.Error("should fail")
	}
	if _, err := ECDH(s.PrivateKey(), nil, nil); err == nil {
		t.Error("should fail")
	}
}

func TestKeyReflectionAttack(t *testing.T) {
	k, err := Curve25519Generate(RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ECDH(k.PrivateKey(), k.PublicKey(), k.PublicKey()); err == nil {
		t.Error("should fail")
	}
	if _, err := ECDH(k.PrivateKey(), k.PublicKey(), nil); err == nil {
		t.Error("should fail")
	}
}
