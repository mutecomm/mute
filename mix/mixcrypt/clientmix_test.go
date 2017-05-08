// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mixcrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/mix/mixaddr"
	"github.com/mutecomm/mute/mix/nymaddr"
	"github.com/mutecomm/mute/util/times"
	"golang.org/x/crypto/curve25519"
)

var testMessage = []byte(`
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way. This message needs to be 4096 byte long, no less, more is permissible. It's because the constants are that way.
`)

func TestClientMixHeader(t *testing.T) {
	testData := ClientMixHeader{
		MessageType:    MessageTypeRelay,
		SenderMinDelay: 10,
		SenderMaxDelay: 30,
		Token:          []byte("Token"),
		Address:        []byte("Address"),
		RevokeID:       []byte("RevokeID"),
	}
	asn := testData.Marshal()
	testData2, lenB, err := new(ClientMixHeader).Unmarshal(asn)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}
	if len(asn) != int(lenB) {
		t.Errorf("Bad length returned: %d != %d", len(asn), lenB)
	}
	if !bytes.Equal(testData.Token, testData2.Token) {
		t.Error("Decode: Token")
	}
	if !bytes.Equal(testData.Address, testData2.Address) {
		t.Error("Decode: Address")
	}
	if !bytes.Equal(testData.RevokeID, testData2.RevokeID) {
		t.Error("Decode: RevokeID")
	}
	if testData.MessageType != testData2.MessageType {
		t.Error("Decode: MessageType")
	}
	if testData.SenderMinDelay != testData2.SenderMinDelay {
		t.Error("Decode: SenderMinDelay")
	}
	if testData.SenderMaxDelay != testData2.SenderMaxDelay {
		t.Error("Decode: SenderMaxDelay")
	}
}

func TestSendReceiveForward(t *testing.T) {
	NextHop := "mix1@mute.berlin"
	NextHopPrivKey, _ := genNonce()
	NextHopPubKey := new([KeySize]byte)
	curve25519.ScalarBaseMult(NextHopPubKey, NextHopPrivKey)
	clientHeader := ClientMixHeader{
		SenderMinDelay: 10,
		SenderMaxDelay: 30,
		Token:          []byte("Example token"),
	}
	encMessage, nextaddress, err := clientHeader.NewForwardMessage(NextHop, NextHopPubKey, testMessage)
	if err != nil {
		t.Fatalf("NewForwardMessage: %s", err)
	}
	if nextaddress != NextHop {
		t.Error("Bad NextHop")
	}
	receiveData, err := ReceiveMessage(func(*[KeySize]byte) *[KeySize]byte { return NextHopPrivKey }, encMessage)
	if err != nil {
		t.Fatalf("ReceiveMessage: %s", err)
	}
	if !bytes.Equal(receiveData.Message, testMessage) {
		t.Error("Messages dont match")
	}
	if !bytes.Equal(receiveData.MixHeader.Token, clientHeader.Token) {
		t.Error("Tokens dont match")
	}
	if string(receiveData.MixHeader.Address) != NextHop {
		t.Error("Next hop doesnt match")
	}
	if receiveData.MixHeader.SenderMaxDelay != clientHeader.SenderMaxDelay {
		t.Error("Max delay does not match")
	}
	if receiveData.MixHeader.SenderMinDelay != clientHeader.SenderMinDelay {
		t.Error("Min delay does not match")
	}
	if len(receiveData.UniqueTest) != 1 {
		t.Error("Only one uniquetest should be done")
	}
}

func TestSendReceiveRelay(t *testing.T) {
	_, privkey, _ := ed25519.GenerateKey(rand.Reader)
	mixAddress := "mix01@mute.berlin"
	recAddress := "mailbox001@001."
	pseudonym := []byte("Pseudonym001")
	pseudoHash := sha256.Sum256(pseudonym)
	kl := mixaddr.New(privkey, mixAddress, 7200, 24*3600, "/tmp/mixkeydir")
	kl.AddKey()
	stmt := kl.GetStatement()
	// AddressTemplate contains parameters for address creation
	addressTemplate := nymaddr.AddressTemplate{
		Secret: []byte("something super-secret"),

		MixCandidates: stmt.Addresses,

		Expire:    times.Now() + 3600,
		SingleUse: true,
		MinDelay:  10,
		MaxDelay:  30,
	}
	NymAddress, err := addressTemplate.NewAddress([]byte(recAddress), pseudoHash[:])
	if err != nil {
		t.Fatalf("NewAddress: %s", err)
	}
	clientHeader := ClientMixHeader{
		SenderMinDelay: 10,
		SenderMaxDelay: 30,
		Token:          []byte("Example token"),
	}
	encMessage, nextaddress, err := clientHeader.NewRelayMessage(NymAddress, testMessage)
	if err != nil {
		t.Fatalf("NewRelayMessage: %s", err)
	}
	if nextaddress != mixAddress {
		t.Error("Bad NextHop")
	}
	receiveData, err := ReceiveMessage(kl.GetPrivateKey, encMessage)
	if err != nil {
		t.Fatalf("ReceiveMessage: %s", err)
	}
	if len(receiveData.UniqueTest) != 2 {
		t.Error("SingleUse nymaddress, exactly two uniquetests necessary")
	}
	if !bytes.Equal(receiveData.Message, testMessage) {
		t.Error("Messages dont match")
	}
	if !bytes.Equal(receiveData.MixHeader.Token, clientHeader.Token) {
		t.Error("Tokens dont match")
	}
	if receiveData.MixHeader.SenderMaxDelay != clientHeader.SenderMaxDelay {
		t.Error("Max delay does not match")
	}
	if receiveData.MixHeader.SenderMinDelay != clientHeader.SenderMinDelay {
		t.Error("Min delay does not match")
	}
	newMessage, nextaddress, err := receiveData.Send()
	if err != nil {
		t.Fatalf("Send-Along: %s", err)
	}
	if nextaddress != "mailbox001@001.mute.one" {
		t.Error("Bad address expansion")
	}
	decMessage, nym, err := ReceiveFromMix(addressTemplate, []byte(recAddress), newMessage)
	if err != nil {
		t.Fatalf("ReceiveFromMix: %s", err)
	}
	if !bytes.Equal(nym, pseudoHash[:]) {
		t.Error("Nyms do not match")
	}
	if !bytes.Equal(decMessage, testMessage) {
		t.Error("Message decryption failed")
	}
}
