package keypool

import (
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path"
	"testing"

	"github.com/mutecomm/mute/serviceguard/common/signkeys"

	"github.com/agl/ed25519"
	"github.com/ronperry/cryptoedge/eccutil"
)

var keydirectory string

func init() {
	keydirectory = path.Join(os.TempDir(), "serviceguard_test", "keydir")
	os.MkdirAll(keydirectory, 0700)
}

func TestGenerator(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	kp := New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	kp.Generator.PrivateKey = privkey
	kp.Generator.PublicKey = pubkey
	kp.AddVerifyKey(pubkey)
	_ = pubkey
	key, _, err := kp.Current()
	if err != nil {
		t.Fatalf("Current failed: %s", err)
	}
	pkey, err := kp.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Errorf("Lookup failed: %s", err)
	}
	_ = pkey
}
