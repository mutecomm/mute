package sortedmap

import (
	"crypto/rand"
	"testing"

	"github.com/agl/ed25519"
)

func TestConv(t *testing.T) {
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Keygen failed: %s", err)
	}
	sm := make(StringMap)
	sm["alpha"] = "first"
	sm["beta"] = "second"
	sm["gamma"] = "third"
	sm["delta"] = "fourth"
	ss := sm.Sort()
	if ss[0].K != "alpha" || ss[0].V != "first" {
		t.Error("Bad first")
	}
	if ss[3].K != "gamma" || ss[3].V != "third" {
		t.Error("Bad last")
	}
	sig := ss.Sign(10, privkey)
	if !ss.Verify(10, pubkey[:], sig) {
		t.Error("Signature verify failed")
	}
	if ss.Verify(11, pubkey[:], sig) {
		t.Error("Signature verification MUST fail on bad date")
	}
	sig[3] = ^sig[3]
	if ss.Verify(10, pubkey[:], sig) {
		t.Error("Signature verification MUST fail on bad signature")
	}
}
