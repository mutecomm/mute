package cipher

import (
	"crypto/hmac"
	"testing"

	"github.com/mutecomm/mute/encode/base64"
)

const (
	encKey = "LMz+5UiMGF0mwsgzp1MkKGVq7dDmT/adgCqpeOBAa1wf3iL99NgpQt2cbebIMgda/3UTKiiLcU33G0md4ZqpAw=="
	encBuf = "G3UKOqaZZxtX8mjmBVK5QfFS2UriqqVWZ3pxsAeeNkjl1NK0qG1WLai9g0N0hPsWjH8P5PkQp+2GtMC5trBAyA=="
	encMac = "T74IQ0wVfVHkDiJ9kegYJS3gXfz2jWIVGFwbl1XM5ZvJQYX/IWy0YTph8UhzDfL4Y6F8fmM7FXOF5pc1cYmgdA=="
)

func TestHMAC(t *testing.T) {
	key, err := base64.Decode(encKey)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := base64.Decode(encBuf)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := base64.Decode(encMac)
	if err != nil {
		t.Fatal(err)
	}
	nmac := HMAC(key, buf)
	if !hmac.Equal(nmac, mac) {
		t.Fatal("HMACs differ")
	}
}
