package cipher

import (
	"bytes"
	"testing"
)

func TestNaClBox(t *testing.T) {
	if _, err := NaClBoxGenerate(RandFail); err == nil {
		t.Error("should fail")
	}
	n, err := NaClBoxGenerate(RandReader)
	if err != nil {
		t.Fatal(err)
	}
	crrpt := []byte("corrupt")
	pubKey := n.PublicKey()
	privKey := n.PrivateKey()
	if err := n.SetPublicKey(crrpt); err == nil {
		t.Error("should fail")
	}
	if err := n.SetPublicKey(pubKey); err != nil {
		t.Fatal(err)
	}
	if err := n.SetPrivateKey(crrpt); err == nil {
		t.Error("should fail")
	}
	if err := n.SetPrivateKey(privKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubKey, n.PublicKey()) {
		t.Error("public keys differ")
	}
	if !bytes.Equal(privKey, n.PrivateKey()) {
		t.Error("private keys differ")
	}
}
