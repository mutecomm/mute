package mixcrypt

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestCalculateSharedSecret(t *testing.T) {
	var pubkey1, privkey1, pubkey2, privkey2 [KeySize]byte
	testData := []byte("Some data to be tested")
	io.ReadFull(Rand, privkey1[:])
	io.ReadFull(Rand, privkey2[:])
	curve25519.ScalarBaseMult(&pubkey1, &privkey1)
	curve25519.ScalarBaseMult(&pubkey2, &privkey2)
	secret, nonce := CalculateSharedSecret(nil, nil, nil)
	if secret != nil || nonce != nil {
		t.Error("CalculateSharedSecret without parameters must return nils")
	}
	secret1, nonce1 := CalculateSharedSecret(&pubkey1, &privkey2, nil)
	secret2, nonce2 := CalculateSharedSecret(&pubkey2, &privkey1, nonce1)
	if *secret1 != *secret2 {
		t.Error("Secrets do not match")
	}
	if *nonce1 != *nonce2 || nonce1 == nil {
		t.Error("Nonce creation failed")
	}
	encryptedData, err := GCMEncrypt(nonce1[:], secret1[:], testData)
	if err != nil {
		t.Fatalf("GCMEncrypt: %s", err)
	}
	decryptedData, err := GCMDecrypt(nonce2[:], secret2[:], encryptedData)
	if err != nil {
		t.Fatalf("GCMDecrypt: %s", err)
	}
	if !bytes.Equal(testData, decryptedData) {
		t.Error("Pre/Post encryption data do not match")
	}
	encryptedData, err = Encrypt(&pubkey2, &privkey1, testData)
	if err != nil {
		t.Errorf("Encrypt failed: %s", err)
	}
	decryptedData, err = Decrypt(func(*[KeySize]byte) *[KeySize]byte { return &privkey2 }, encryptedData)
	if err != nil {
		t.Errorf("Decrypt failed: %s", err)
	}
	if !bytes.Equal(testData, decryptedData) {
		t.Error("Pre/Post encryption data do not match")
	}
}
