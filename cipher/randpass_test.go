package cipher

import (
	"testing"
)

func TestRandPass(t *testing.T) {
	p1 := RandPass(RandReader)
	p2 := RandPass(RandReader)
	if p1 == p2 {
		t.Fatal("should differ")
	}
}

func TestRandPassPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("should panic")
		}
	}()
	RandPass(RandFail)
}
