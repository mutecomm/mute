// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"testing"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/msg/session/memstore"
)

func TestGenerateMessageKeys(t *testing.T) {
	rk, err := base64.Decode("HdxGXLlSNRhwydGkd4QISqquIQirNtCD")
	if err != nil {
		t.Fatal(err)
	}
	ssp, err := base64.Decode("XRzQmXbf1TRTMVOpU9354Vx8mR32im0gK3IzzVPI/JE=")
	if err != nil {
		t.Fatal(err)
	}
	rp, err := base64.Decode("y2mzWFL3I16rkNPeMFleX/6a8Ynx93L8oirS4uSYTPo=")
	if err != nil {
		t.Fatal(err)
	}
	var rootKey [24]byte
	var senderSessionPub [32]byte
	var recipientPub [32]byte
	copy(rootKey[:], rk)
	copy(senderSessionPub[:], ssp)
	copy(recipientPub[:], rp)
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	h := "hash"
	ms := memstore.New()
	err = generateMessageKeys(a, b, &rootKey, false, h, &senderSessionPub,
		&recipientPub, ms)
	if err != nil {
		t.Fatal(err)
	}

	rootKeyHash, err := ms.GetRootKeyHash(a, b, h)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.Encode(rootKeyHash[:])
	if b64 != "IiWB61ml7jLQyBx6G3Hak9DoiXxJZGBCesWJ2pesme963rcjWsusi8gdgUic8WhSucqPvsWzXxxzJetJmVJFaw==" {
		t.Error("wrong rootKeyHash")
	}

	key, err := ms.GetMessageKey(a, b, h, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "W0hBJMhJXE8jintu5CoQl+Fr7s0FIlQx3DBGLadUy2smaPMTqOppEvrhr4ch5FNRLCrwsj7/n9Htdf4qe8G6rQ==" {
		t.Error("wrong message key (sender, 0)")
	}

	key, err = ms.GetMessageKey(a, b, h, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "R1/zJ3bMIWGq6VVVb6jMOXbQvDNv1MGnbgF3BHAaAyhi29zwt6KdksMqIn8vdt9lW8NhjRhOoTt7oV2LH2ZWfQ==" {
		t.Error("wrong message key (recipient, 0)")
	}

	key, err = ms.GetMessageKey(a, b, h, true, 49)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "8ChnQU0MEuoN4snKjzkVWdAt0tW2pA31v4wDbpNU2nL63ea8ck0ISgrScIFlHeUm1X0GQ1yG+k3/1TojrwP/YQ==" {
		t.Error("wrong message key (sender, 49)")
	}

	key, err = ms.GetMessageKey(a, b, h, false, 49)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "9M98fdyq9z5gb9seYUPcw0Gw1Ec5H3fF0EPVVUdfw7OPnGYfolAJ+UVvgqdzkpklCdx6r2SqyhV3Sbes2QEd6A==" {
		t.Error("wrong message key (recipient, 49)")
	}
}
