// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"bytes"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg/session/memstore"
)

func TestGenerateMessageKeys(t *testing.T) {
	defer log.Flush()
	rk, err := base64.Decode("CH9NjvU/usWcT0vNgiiUHNt9UFgWKneEPRgN0HIvlP0=")
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
	var rootKey [32]byte
	var senderSessionPub [32]byte
	var recipientPub [32]byte
	copy(rootKey[:], rk)
	copy(senderSessionPub[:], ssp)
	copy(recipientPub[:], rp)
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	ms1 := memstore.New()

	sKey := "sender"
	sKey += "recipient"
	sKey += base64.Encode(cipher.SHA512(senderSessionPub[:]))
	sKey += base64.Encode(cipher.SHA512(recipientPub[:]))
	senderSessionKey := base64.Encode(cipher.SHA512([]byte(sKey)))

	sKey = "recipient"
	sKey += "sender"
	sKey += base64.Encode(cipher.SHA512(recipientPub[:]))
	sKey += base64.Encode(cipher.SHA512(senderSessionPub[:]))
	recipientSessionKey := base64.Encode(cipher.SHA512([]byte(sKey)))

	err = generateMessageKeys(a, b, "sender", "recipient", &rootKey, false,
		&senderSessionPub, &recipientPub, NumOfFutureKeys, ms1)
	if err != nil {
		t.Fatal(err)
	}

	rootKeyHash, err := ms1.GetRootKeyHash(senderSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.Encode(rootKeyHash[:])
	if b64 != "KJgsEto4kssCEBJAgGJTt2fJ6/FJqMupevapOwtkdgjF0z0VNI8Zzv15hwRVfZPGrGtgc5AGaeZiyao2wZLE2Q==" {
		t.Errorf("wrong rootKeyHash: %s", b64)
	}

	key, err := ms1.GetMessageKey(senderSessionKey, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "1EaJ70EOJ1tEYEksbmv1FOgmG+SB0A0LMcx4gp687NdrEmeb/T04GYneFw9hAenUGsgkOjGtySLIL36xqQlgmw==" {
		t.Errorf("wrong message key (sender, 0): %s", b64)
	}

	key, err = ms1.GetMessageKey(senderSessionKey, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "o5K0K5cKuWEAMX6g1Cbv2yrcddg2eoB7PhJjtECO1IQsVbNkTf/FqiW4X2/Tmy6XbXhEoysdYPJL4bokoINvsA==" {
		t.Errorf("wrong message key (recipient, 0): %s", b64)
	}

	key, err = ms1.GetMessageKey(senderSessionKey, true, 49)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "r1TwPGq7WF5ysN2ZFyX4ZmnnNxMzH3hAAOfWew8mIND7BqFPSY01H/A7U48awcOwFd9pCnVXd5yc5W0TYvON/Q==" {
		t.Errorf("wrong message key (sender, 49): %s", b64)
	}

	key, err = ms1.GetMessageKey(senderSessionKey, false, 49)
	if err != nil {
		t.Fatal(err)
	}
	b64 = base64.Encode(key[:])
	if b64 != "d45Eic1g95nDrSncvo4FML/zha9lHtnDO/9kDyARQP3AgguhXD1bjw+/ep8MkI91qjAlnmHcsxVOAEEMbecmaQ==" {
		t.Errorf("wrong message key (recipient, 49): %s", b64)
	}

	// generate additional keys from chainKey
	chainKey, err := ms1.GetChainKey(senderSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	err = generateMessageKeys(a, b, "sender", "recipient", chainKey, false,
		&senderSessionPub, &recipientPub, NumOfFutureKeys, ms1)
	if err != nil {
		t.Fatal(err)
	}

	// generate all keys at the same time
	ms2 := memstore.New()
	copy(rootKey[:], rk)
	err = generateMessageKeys(a, b, "sender", "recipient", &rootKey, true,
		&senderSessionPub, &recipientPub, 2*NumOfFutureKeys, ms2)
	if err != nil {
		t.Fatal(err)
	}
	n1, err := ms1.NumMessageKeys(senderSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := ms2.NumMessageKeys(recipientSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n2 {
		t.Error("number of message keys differ")
	}

	// compare keys
	k1, err := ms1.GetMessageKey(senderSessionKey, true, NumOfFutureKeys-1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ms2.GetMessageKey(recipientSessionKey, false, NumOfFutureKeys-1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1[:], k2[:]) {
		t.Error("keys differ")
	}

	k1, err = ms1.GetMessageKey(senderSessionKey, true, 2*NumOfFutureKeys-1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err = ms2.GetMessageKey(recipientSessionKey, false, 2*NumOfFutureKeys-1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1[:], k2[:]) {
		t.Error("keys differ")
	}
}
