package msgid

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/uid/identity"
)

func TestMessageID(t *testing.T) {
	a := "alice@mute.berlin"
	j := "john@mute.berlin"
	msgid, err := Generate(a, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(j, cipher.RandReader); err != identity.ErrNotMapped {
		t.Error("err != identity.ErrNotMapped")
	}
	if _, err := Generate("", cipher.RandReader); err != identity.ErrNotMapped {
		t.Error("err != identity.ErrNotMapped")
	}
	if _, err := Generate(a, cipher.RandFail); err != io.EOF {
		t.Error("err != io.EOF")
	}
	nym := Parse(msgid)
	if nym != a {
		t.Error("nym != a")
	}
	parts := strings.Split(msgid, "-")
	if len(parts) != 4 {
		t.Fatal("len(parts) != 4")
	}
	if parts[0] != a {
		t.Error("parts[0] != a")
	}
	if parts[1] != time.Now().UTC().Format("2006") {
		t.Error("parts[1] != year")
	}
	if parts[2] != time.Now().UTC().Format("01") {
		t.Error("parts[2] != month")
	}
	if len(parts[3]) != 16 {
		t.Error("len(parts[3]) != 16")
	}
	if Parse(a) != "" {
		t.Error("should fail")
	}
	if Parse("") != "" {
		t.Error("should fail")
	}
}
