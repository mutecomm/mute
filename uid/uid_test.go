package uid

import (
	"bytes"
	"io"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
)

func TestUIDMessage(t *testing.T) {
	uid, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if uid.Localpart() != "test" {
		t.Errorf("wrong localpart")
	}
	if uid.Domain() != "mute.berlin" {
		t.Errorf("wrong domain")
	}
	if err := uid.VerifySelfSig(); err != nil {
		t.Error(err)
	}
	privkey := uid.PrivateSigKey()
	if err := uid.SetPrivateSigKey(privkey); err != nil {
		t.Fatal(err)
	}
	if privkey != uid.PrivateSigKey() {
		t.Error("private keys differ")
	}
	if privkey != base64.Encode(uid.PrivateSigKey64()[:]) {
		t.Error("private keys differ")
	}
	jsn := uid.JSON()
	jsnUID, err := NewJSON(string(jsn))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsn, jsnUID.JSON()) {
		t.Errorf("UIDs differ")
	}
	if err := jsnUID.SetPrivateSigKey(privkey); err != nil {
		t.Fatal(err)
	}
	if err := jsnUID.SetPrivateSigKey("!"); err == nil {
		t.Error("should fail")
	}
	up, err := uid.Update(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.VerifyUserSig(uid); err != nil {
		t.Error(err)
	}
}

func TestIncrementCheck(t *testing.T) {
	uid, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	up, err := uid.Update(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	up2, err := up.Update(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := up2.VerifyUserSig(uid); err != ErrIncrement {
		t.Error("should fail")
	}
	if _, err := uid.Update(cipher.RandFail); err == nil {
		t.Error("should fail")
	}
}

func TestSelfSig(t *testing.T) {
	uid, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	uid.SELFSIGNATURE = ""
	if err := uid.VerifySelfSig(); err != ErrInvalidSelfSig {
		t.Error("should fail")
	}
	uid.SELFSIGNATURE = "!"
	if err := uid.VerifySelfSig(); err == nil {
		t.Error("should fail")
	}
	uid.SELFSIGNATURE = ""
	uid.UIDCONTENT.SIGKEY.PUBKEY = "!"
	if err := uid.VerifySelfSig(); err == nil {
		t.Error("should fail")
	}
}

func TestUserSig(t *testing.T) {
	uid, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	up, err := uid.Update(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	up.USERSIGNATURE = ""
	if err := up.VerifyUserSig(uid); err != ErrInvalidUserSig {
		t.Error("should fail")
	}
	up.USERSIGNATURE = "!"
	if err := up.VerifyUserSig(uid); err == nil {
		t.Error("should fail")
	}
	up.USERSIGNATURE = ""
	uid.UIDCONTENT.SIGKEY.PUBKEY = "!"
	if err := up.VerifyUserSig(uid); err == nil {
		t.Error("should fail")
	}
}

func TestEscrow(t *testing.T) {
	if _, err := Create("test@mute.berlin", true, "", "", Strict, cipher.RandReader); err != nil {
		t.Fatal(err)
	}
}

func TestCreateFail(t *testing.T) {
	if _, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandFail); err == nil {
		t.Error("should fail")
	}
	if _, err := Create("test@mute.berlin", true, "", "", Strict, io.LimitReader(cipher.RandReader, 1)); err == nil {
		t.Error("should fail")
	}
	if _, err := NewJSON(""); err == nil {
		t.Error("should fail")
	}
	if _, err := NewJSONReply(""); err == nil {
		t.Error("should fail")
	}
}

func TestUIDMessageReply(t *testing.T) {
	uid, err := Create("alice@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cipher.Ed25519Generate(cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	// encrypt
	UIDHash, UIDIndex, UIDMessageEncrypted := uid.Encrypt()
	// create reply
	UIDMessageReply := CreateReply(UIDMessageEncrypted, "", 0, key)
	reply := UIDMessageReply.JSON()
	// JSON encoding/decoding
	jsnReply, err := NewJSONReply(string(reply))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, jsnReply.JSON()) {
		t.Errorf("replies differ")
	}
	// decrypt
	idx, msg, err := UIDMessageReply.Decrypt(UIDHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(idx, UIDIndex) {
		t.Errorf("indices differ")
	}
	if !bytes.Equal(msg.JSON(), uid.JSON()) {
		t.Errorf("UIDs differ")
	}
	// wrong UIDHash
	hash := make([]byte, 32)
	if _, _, err := UIDMessageReply.Decrypt(hash); err == nil {
		t.Error("should fail")
	}
	// verify signature
	sigKey := base64.Encode(key.PublicKey()[:])
	if err := UIDMessageReply.VerifySrvSig(uid, sigKey); err != nil {
		t.Error(err)
	}
	// corrupt encrypte message
	UIDMessageReply.ENTRY.UIDMESSAGEENCRYPTED = "!"
	if _, _, err := UIDMessageReply.Decrypt(UIDHash); err == nil {
		t.Error("should fail")
	}
	// corrupt signature
	sig := UIDMessageReply.SERVERSIGNATURE
	UIDMessageReply.SERVERSIGNATURE = "!"
	if err := UIDMessageReply.VerifySrvSig(uid, sigKey); err == nil {
		t.Error("should fail")
	}
	// corrupt signature key
	UIDMessageReply.SERVERSIGNATURE = sig // restore signature
	if err := UIDMessageReply.VerifySrvSig(uid, "!"); err == nil {
		t.Error("should fail")
	}
	// invalid signature
	UIDMessageReply.SERVERSIGNATURE = ""
	if err := UIDMessageReply.VerifySrvSig(uid, sigKey); err == nil {
		t.Error("should fail")
	}
}

func TestNonceSignature(t *testing.T) {
	msg, err := Create("test@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, signature := msg.SignNonce()
	if err := VerifyNonce(msg.UIDCONTENT.SIGKEY.PUBKEY, nonce, signature); err != nil {
		t.Error(err)
	}
	if err := VerifyNonce(msg.UIDCONTENT.SIGKEY.PUBKEY, nonce, "!"); err == nil {
		t.Error("should fail")
	}
	if err := VerifyNonce("!", nonce, signature); err == nil {
		t.Error("should fail")
	}
	if err := VerifyNonce(msg.UIDCONTENT.SIGKEY.PUBKEY, nonce+1, signature); err != ErrInvalidNonceSig {
		t.Error("should fail")
	}
}

func TestSigKeyHash(t *testing.T) {
	msg, err := Create("alice@mute.berlin", false, "", "", Strict, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Identity() != "alice@mute.berlin" {
		t.Error("wrong identity")
	}
	sigKeyHash, err := msg.SigKeyHash()
	if err != nil {
		t.Fatal(err)
	}
	sigPubKey, err := base64.Decode(msg.SigPubKey())
	if err != nil {
		t.Fatal(err)
	}
	if sigKeyHash != base64.Encode(cipher.SHA512(cipher.SHA512(sigPubKey))) {
		t.Fatal("SIGKEYHASHs differ")
	}

	privKey := msg.PrivateEncKey()
	if err := msg.SetPrivateEncKey(privKey); err != nil {
		t.Fatal(err)
	}
	if privKey != msg.PrivateEncKey() {
		t.Error("private keys differ")
	}
}
