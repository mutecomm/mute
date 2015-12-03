// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/times"
)

func TestHeaderPadding(t *testing.T) {
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
	h, err := newHeader(aliceUID, bobUID, bobKE, aliceKE, nil, nil,
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
	_, err = newHeaderPacket(h, recipientIdentityPub,
		senderHeaderKey.PrivateKey(), cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
}
