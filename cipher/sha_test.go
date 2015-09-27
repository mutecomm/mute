// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"encoding/hex"
	"testing"
)

func TestSHA1(t *testing.T) {
	if hex.EncodeToString(SHA1([]byte(""))) != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Error("SHA1(\"\") != \"da39a3ee5e6b4b0d3255bfef95601890afd80709\")")
	}
	if hex.EncodeToString(SHA1([]byte("abc"))) != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Error("SHA1(\"abc\") != \"a9993e364706816aba3e25717850c26c9cd0d89d\")")
	}
	if hex.EncodeToString(SHA1([]byte("Cypherpunks write code!"))) != "62d5aa459b32009b8b0e307daa99a19cf3fa40d4" {
		t.Error("SHA1(\"Cypherpunks write code!\") != \"62d5aa459b32009b8b0e307daa99a19cf3fa40d4\")")
	}
}

func TestSHA256(t *testing.T) {
	if hex.EncodeToString(SHA256([]byte(""))) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Error("SHA256(\"\") != \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\")")
	}
	if hex.EncodeToString(SHA256([]byte("abc"))) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Error("SHA256(\"abc\") != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\")")
	}
	if hex.EncodeToString(SHA256([]byte("Cypherpunks write code!"))) != "5dcc6632db5b7b44ef475b88466f5526fe9bdfaea1415de059c55262095416b2" {
		t.Error("SHA256(\"Cypherpunks write code!\") != \"5dcc6632db5b7b44ef475b88466f5526fe9bdfaea1415de059c55262095416b2\")")
	}
}

func TestSHA512(t *testing.T) {
	if hex.EncodeToString(SHA512([]byte(""))) != "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" {
		t.Error("SHA512(\"\") != \"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\")")
	}
	if hex.EncodeToString(SHA512([]byte("abc"))) != "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" {
		t.Error("SHA512(\"abc\") != \"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f\")")
	}
	if hex.EncodeToString(SHA512([]byte("Cypherpunks write code!"))) != "e3790418bd144e661666d526df8ebbb43b9c9fc50a9fcc02be5c067f04ce4e455e58847c78a6486c9b3b09f16ca85178c7dc22a01f3fef02a8d4141a54aef4d8" {
		t.Error("SHA512(\"Cypherpunks write code!\") != \"e3790418bd144e661666d526df8ebbb43b9c9fc50a9fcc02be5c067f04ce4e455e58847c78a6486c9b3b09f16ca85178c7dc22a01f3fef02a8d4141a54aef4d8\")")
	}
}
