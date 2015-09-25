package client

import (
	"bytes"
	"errors"
	"testing"
)

var ErrTestError = errors.New("Test Error")
var testdata = MessageOutput{
	Message:   []byte("Test Message"),
	To:        "mix@mute.berlin",
	From:      "client@mute.berlin",
	RevokeID:  []byte("RevokeID"),
	SMTPPort:  25,
	SmartHost: "mix.mute.berlin",
	CACert:    nil,
	Error:     ErrTestError,
	Resend:    true,
}

func TestMarshal(t *testing.T) {
	registerError(ErrTestError)
	marshalled := testdata.Marshal()
	testdata2 := marshalled.Unmarshal()
	if !bytes.Equal(testdata.Message, testdata2.Message) {
		t.Error("Remarshall error: Message")
	}
	if testdata.To != testdata2.To {
		t.Error("Remarshall error: To")
	}
	if testdata.From != testdata2.From {
		t.Error("Remarshall error: From")
	}
	if !bytes.Equal(testdata.RevokeID, testdata2.RevokeID) {
		t.Error("Remarshall error: RevokeID")
	}
	if testdata.SMTPPort != testdata2.SMTPPort {
		t.Error("Remarshall error: SMTPPort")
	}
	if testdata.SmartHost != testdata2.SmartHost {
		t.Error("Remarshall error: SmartHost")
	}
	if !bytes.Equal(testdata.CACert, testdata2.CACert) {
		t.Error("Remarshall error: CACert")
	}
	if testdata.Error != testdata2.Error {
		t.Error("Remarshall error: Error")
	}
	if testdata.Resend != testdata2.Resend {
		t.Error("Remarshall error: Resend")
	}
	testdata.Error = nil
	marshalled = testdata.Marshal()
	testdata2 = marshalled.Unmarshal()
	if !bytes.Equal(testdata.Message, testdata2.Message) {
		t.Error("Remarshall error: Message")
	}
	if testdata.To != testdata2.To {
		t.Error("Remarshall error: To")
	}
	if testdata.From != testdata2.From {
		t.Error("Remarshall error: From")
	}
	if !bytes.Equal(testdata.RevokeID, testdata2.RevokeID) {
		t.Error("Remarshall error: RevokeID")
	}
	if testdata.SMTPPort != testdata2.SMTPPort {
		t.Error("Remarshall error: SMTPPort")
	}
	if testdata.SmartHost != testdata2.SmartHost {
		t.Error("Remarshall error: SmartHost")
	}
	if !bytes.Equal(testdata.CACert, testdata2.CACert) {
		t.Error("Remarshall error: CACert")
	}
	if testdata.Error != testdata2.Error {
		t.Error("Remarshall error: Error")
	}
	if testdata.Resend != testdata2.Resend {
		t.Error("Remarshall error: Resend")
	}
	marshalled2 := testdata2.Marshal()
	testdata3 := marshalled2.Unmarshal()
	_, _ = testdata2, testdata3
}
