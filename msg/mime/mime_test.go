package mime

import (
	"bytes"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/mail"
	"reflect"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/msg/msgid"
	"github.com/mutecomm/mute/util/tests"
)

const testBoundary = "e8b4973b051ba38d7dd15c21c0949e3c77aaf9a55c52224fb2c112842123--"

func TestMailHeader(t *testing.T) {
	from := "alice@mute.berlin"
	to := "bob@mute.berlin"
	messageID, err := msgid.Generate(from, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	var email bytes.Buffer
	header := Header{
		From:      from,
		To:        to,
		MessageID: messageID,
	}
	err = mailHeader(&email, header, "", testBoundary)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(&email)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("From") != from {
		t.Error("wrong 'From' header")
	}
	if msg.Header.Get("To") != to {
		t.Error("wrong 'To' header")
	}
	if _, err := msg.Header.AddressList("Cc"); err != mail.ErrHeaderNotPresent {
		t.Error("should not contain 'Cc' fields")
	}
	if msg.Header.Get("Message-ID") != messageID {
		t.Error("wrong 'Message-ID' header")
	}
	if msg.Header.Get("MIME-Version") != "1.0" {
		t.Error("wrong 'MIME-Version' header")
	}
	mediaType, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Error(err)
	} else if mediaType != "multipart/mixed" {
		t.Error("wrong 'Content-Type' header")
	}
	c := "carol@mute.berlin"
	d := "dan@mute.berlin"
	cc := []string{c, d}
	inReplyTo, err := msgid.Generate(to, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	email.Reset()
	header = Header{
		From:      from,
		To:        to,
		Cc:        cc,
		MessageID: messageID,
		InReplyTo: inReplyTo,
	}
	err = mailHeader(&email, header, "subject", testBoundary)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = mail.ReadMessage(&email)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("From") != from {
		t.Error("wrong 'From' header")
	}
	if msg.Header.Get("To") != to {
		t.Error("wrong 'To' header")
	}
	addressList, err := msg.Header.AddressList("Cc")
	if err != nil {
		t.Fatal(err)
	}
	if addressList[0].Address != c {
		t.Error("wrong first 'Cc' header entry")
	}
	if addressList[1].Address != d {
		t.Error("wrong second 'Cc' header entry")
	}
	if msg.Header.Get("Subject") != "subject" {
		t.Error("wrong 'Subject' header ")
	}
	if msg.Header.Get("Message-ID") != messageID {
		t.Error("wrong 'Message-ID' header")
	}
	if msg.Header.Get("In-Reply-To") != inReplyTo {
		t.Error("wrong 'In-Reply-To' header")
	}
	if msg.Header.Get("MIME-Version") != "1.0" {
		t.Error("wrong 'MIME-Version' header")
	}
	mediaType, _, err = mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Error(err)
	} else if mediaType != "multipart/mixed" {
		t.Error("wrong 'Content-Type' header")
	}
}

func TestMultipartMIME(t *testing.T) {
	var mime bytes.Buffer
	writer := multipart.NewWriter(&mime)
	if err := multipartMIME(writer, tests.Message1, nil); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	mime.Reset()
	writer = multipart.NewWriter(&mime)
	err := multipartMIME(writer, tests.Message1,
		[]*Attachment{
			&Attachment{
				Filename:    "message.txt",
				Reader:      bytes.NewBufferString(tests.Message2),
				ContentType: "application/octet-stream",
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNew(t *testing.T) {
	from := "alice@mute.berlin"
	to := "bob@mute.berlin"
	cc := []string{"carol@mute.berlin", "dan@mute.berlin"}
	messageID, err := msgid.Generate(from, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	inReplyTo, err := msgid.Generate(to, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	var email bytes.Buffer
	header := Header{
		From:      from,
		To:        to,
		Cc:        cc,
		MessageID: messageID,
		InReplyTo: inReplyTo,
	}
	err = New(&email, header, tests.Message1,
		[]*Attachment{
			&Attachment{
				Filename: "message.txt",
				Reader:   bytes.NewBufferString(tests.Message2),
			},
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestChunks(t *testing.T) {
	from := "alice@mute.berlin"
	to := "bob@mute.berlin"
	cc := []string{"carol@mute.berlin", "dan@mute.berlin"}
	messageID, err := msgid.Generate(from, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	inReplyTo, err := msgid.Generate(to, cipher.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	var msg bytes.Buffer
	header := Header{
		To:        to,
		From:      from,
		Cc:        cc,
		MessageID: messageID,
		InReplyTo: inReplyTo,
	}
	err = New(&msg, header, testMessage,
		[]*Attachment{
			&Attachment{
				Filename: "quote1.txt",
				Reader:   bytes.NewBufferString(tests.Message1),
				Inline:   true,
			},
			&Attachment{
				Filename:    "quote2.txt",
				Reader:      bytes.NewBufferString(tests.Message2),
				ContentType: "application/octet-stream",
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := EncodeChunks(header, msg.String(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	var res bytes.Buffer
	for i, chunk := range chunks {
		h, part, piece, count, err := DecodeChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(h, &header) {
			t.Error("h != header")
		}
		if piece != uint64(i+1) {
			t.Error("piece != i + 1")
		}
		if count != uint64(len(chunks)) {
			t.Error("count != len(chunks)")
		}
		if _, err := res.WriteString(part); err != nil {
			t.Fatal(err)
		}
	}
	if res.String() != msg.String() {
		t.Error("res != msg")
	}
	h, subject, message, attachments, err := Parse(&res)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h, &header) {
		t.Error("h != header")
	}
	if subject != testSubject {
		t.Error("subject != testSubject")
	}
	if message != testMessage {
		t.Error("message != testMessage")
	}
	if len(attachments) != 2 {
		t.Fatal("len(attachments) != 2")
	}
	// check attachment 1
	att1 := attachments[0]
	if att1.Filename != "quote1.txt" {
		t.Error("att1.Filename != \"quote1.txt\"")
	}
	if att1.ContentType != "text/plain; charset=utf-8" {
		t.Error("att1.ContentType != \"text/plain; charset=utf-8\"")
	}
	msg1, err := ioutil.ReadAll(att1.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg1) != tests.Message1 {
		t.Error("msg1 != tests.Message1")
	}
	if !att1.Inline {
		t.Error("att1 should be inline")
	}
	// check attachment 2
	att2 := attachments[1]
	if att2.Filename != "quote2.txt" {
		t.Error("att2.Filename != \"quote2.txt\"")
	}
	if att2.ContentType != "application/octet-stream" {
		t.Error("att2.ContentType != \"application/octet-stream\"")
	}
	msg2, err := ioutil.ReadAll(att2.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg2) != tests.Message2 {
		t.Error("msg1 != tests.Message1")
	}
	if att2.Inline {
		t.Error("att2 should not be inline")
	}
}
