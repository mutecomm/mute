package cipher

import (
	"bytes"
	"testing"
)

func TestNonce(t *testing.T) {
	if bytes.Equal(Nonce(RandReader), Nonce(RandReader)) {
		t.Error("Nonce() == Nonce() -> bingo!")
	}
}

func TestNoncePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("should panic")
		}
	}()
	Nonce(RandFail)
}
