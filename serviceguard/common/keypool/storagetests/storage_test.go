package storagetests

import (
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path"
	"testing"

	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/keypool/keydb"
	"github.com/mutecomm/mute/serviceguard/common/keypool/keydir"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"

	"github.com/agl/ed25519"
	"github.com/ronperry/cryptoedge/eccutil"
)

var database = "root:root@/spendbook"
var keydirectory string

func init() {
	keydirectory = path.Join(os.TempDir(), "serviceguard_test", "keydir")
	os.MkdirAll(keydirectory, 0700)
}

func TestGenerator(t *testing.T) {
	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	kp := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	err := keydir.Add(kp, keydirectory)
	if err != nil {
		t.Fatalf("Storage KEYDIR addition failed: %s", err)
	}
	err = keydb.Add(kp, database)
	if err != nil {
		t.Fatalf("Storage DATABASE addition failed: %s", err)
	}
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
	kp2 := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	err = keydir.Add(kp2, keydirectory)
	if err != nil {
		t.Fatalf("Storage KEYDIR addition failed: %s", err)
	}
	kp2.Generator.PrivateKey = privkey
	kp2.Generator.PublicKey = pubkey
	kp2.AddVerifyKey(pubkey)
	err = kp2.Load()
	if err != nil {
		t.Errorf("Load failed: %s", err)
	}
	pkey2, err := kp2.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Fatalf("Loaded keys incomplete: %s", err)
	}
	if pkey2.KeyID != pkey.KeyID {
		t.Error("KeyID mismatch")
	}
	if pkey2.Usage != pkey.Usage {
		t.Error("Usage mismatch")
	}
	if pkey2.Signature != pkey.Signature {
		t.Error("Signature mismatch")
	}
	kp3 := keypool.New(signkeys.New(elliptic.P256, rand.Reader, eccutil.Sha1Hash))
	kp3.Generator.PrivateKey = privkey
	kp3.Generator.PublicKey = pubkey
	kp3.AddVerifyKey(pubkey)
	err = keydb.Add(kp3, database)
	if err != nil {
		t.Fatalf("Storage DATABASE addition failed: %s", err)
	}
	pkey3, err := kp3.Lookup(key.PublicKey.KeyID)
	if err != nil {
		t.Fatalf("Fetch does not work: %s", err)
	}
	if pkey3.KeyID != pkey.KeyID {
		t.Error("KeyID mismatch")
	}
	if pkey3.Usage != pkey.Usage {
		t.Error("Usage mismatch")
	}
	if pkey3.Signature != pkey.Signature {
		t.Error("Signature mismatch")
	}
}
