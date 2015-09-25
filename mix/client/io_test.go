package client

import (
	"testing"
)

var message = `Message content, something to read, whatever.
And dont forget the fish.
Fish
is
great.
Message content, something to read, whatever.
Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to fnord read, whatever.Message content, something to read, whatever.
Message content, something to read, whatever.Message content, something to read, whatever.Message content, something to read, whatever.
`

func TestMail(t *testing.T) {
	sendMessage := WriteMail("mix001@mute.berlin", "nym28137213@001.storage.mute.berlin", []byte(message))
	body, err := ReadMail([]byte(sendMessage))
	if err != nil {
		t.Errorf("ReadMail: %s", err)
	}
	if string(body) != message {
		t.Error("Message corrupted")
	}
}
