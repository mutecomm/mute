package msgdb

import (
	"os"
	"testing"

	"github.com/mutecomm/mute/def"
)

func TestMessages(t *testing.T) {
	tmpdir, msgDB, err := createDB()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	defer msgDB.Close()
	a := "alice@mute.berlin"
	b := "bob@mute.berlin"
	if err := msgDB.AddNym(a, a, "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := msgDB.AddContact(a, b, b, "Bob", WhiteList); err != nil {
		t.Fatal(err)
	}
	num, err := msgDB.numberOfMessages()
	if err != nil {
		t.Fatal(err)
	}
	if num != 0 {
		t.Errorf("num != 0 == %d", num)
	}
	err = msgDB.AddMessage(a, b, true, "ping", false, def.MinDelay, def.MaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	err = msgDB.AddMessage(a, b, false, "pong", false, def.MinDelay, def.MaxDelay)
	if err != nil {
		t.Fatal(err)
	}
	num, err = msgDB.numberOfMessages()
	if err != nil {
		t.Fatal(err)
	}
	if num != 2 {
		t.Errorf("num != 2 == %d", num)
	}
	ids, err := msgDB.GetMsgIDs(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Error("len(ids) != 2")
	}
	if ids[0].MsgID != 1 {
		t.Error("ids[0].MsgID != 1")
	}
	if ids[1].MsgID != 2 {
		t.Error("ids[1].MsgID != 2")
	}
	from, to, msg, err := msgDB.GetMessage(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	if from != a {
		t.Error("from != a")
	}
	if to != b {
		t.Error("to != b")
	}
	if msg != "ping" {
		t.Error("msg != \"ping\"")
	}
	from, to, msg, err = msgDB.GetMessage(a, 2)
	if err != nil {
		t.Fatal(err)
	}
	if from != b {
		t.Error("from != b")
	}
	if to != a {
		t.Error("to != a")
	}
	if msg != "pong" {
		t.Error("msg != \"pong\"")
	}
}
