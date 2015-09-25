package cipher

import (
	"testing"
)

func TestRandFail(t *testing.T) {
	b := make([]byte, 32)
	if _, err := RandFail.Read(b); err == nil {
		t.Fatal("should fail")
	}
}
