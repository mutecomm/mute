// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mime implements the MIME encoding used for messages in Mute.
package mime

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
)

// Attachment is a file attachment in Mute. The Content-Type of the MIME
// attachment is determined as follows:
//
//   - if ContentType != "" ContentType is used
//   - if ContentType == "" the Content-Type is derived from Filename
//   - if no Content-Type could be derived "application/octet-stream" is used
type Attachment struct {
	Filename    string    // original filename of attachment
	Reader      io.Reader // the io.Reader to read the attachment from
	ContentType string    // e.g., ""application/pdf"
	Inline      bool      // attachment should be displayed inline
}

// Header is the header used for Mute message encodings.
type Header struct {
	From      string   // mandatory
	To        string   // mandatory
	Cc        []string // optional
	MessageID string   // mandatory
	InReplyTo string   // optional
}

func mailHeader(
	w io.Writer,
	header Header,
	subject string,
	boundary string,
) error {
	fmt.Fprintf(w, "From: %s\r\n", header.From)
	fmt.Fprintf(w, "To: %s\r\n", header.To)
	if header.Cc != nil {
		fmt.Fprintf(w, "Cc: %s\r\n", strings.Join(header.Cc, ","))
	}
	if subject != "" {
		fmt.Fprintf(w, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	}
	fmt.Fprintf(w, "Message-ID: %s\r\n", header.MessageID)
	if header.InReplyTo != "" {
		fmt.Fprintf(w, "In-Reply-To: %s\r\n", header.InReplyTo)
	}
	fmt.Fprintf(w, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(w, "Content-Type: multipart/mixed; boundary=%s\r\n", boundary)
	fmt.Fprintf(w, "\r\n")
	return nil
}

func multipartMIME(
	writer *multipart.Writer,
	msg string,
	attachments []*Attachment,
) error {
	// write message
	mh := make(textproto.MIMEHeader)
	mh.Add("Content-Type", "text/plain")
	mh.Add("Content-Transfer-Encoding", "base64")
	msgWriter, err := writer.CreatePart(mh)
	if err != nil {
		return log.Error(err)
	}
	_, err = io.WriteString(msgWriter, base64.Encode([]byte(msg)))
	if err != nil {
		return log.Error(err)
	}

	// write attachments
	for _, attachment := range attachments {
		mh = make(textproto.MIMEHeader)
		base := filepath.Base(attachment.Filename)
		if attachment.ContentType != "" {
			mh.Add("Content-Type", attachment.ContentType)
		} else {
			ct := mime.TypeByExtension(filepath.Ext(base))
			if ct != "" {
				mh.Add("Content-Type", ct)
			} else {
				mh.Add("Content-Type", "application/octet-stream")
			}
		}
		mh.Add("Content-Transfer-Encoding", "base64")
		mh.Add("Content-Disposition", "attachment; filename="+base)
		if attachment.Inline {
			mh.Add("Content-Disposition", "inline")
		}
		attachmentWriter, err := writer.CreatePart(mh)
		if err != nil {
			return log.Error(err)
		}
		encoder := base64.NewEncoder(attachmentWriter)
		if _, err := io.Copy(encoder, attachment.Reader); err != nil {
			return log.Error(err)
		}
		if err := encoder.Close(); err != nil {
			return log.Error(err)
		}
	}
	return nil
}

func getSubject(msg string) string {
	parts := strings.SplitN(msg, "\n", 2)
	return strings.TrimRight(parts[0], "\r") // better safe than sorry
}

// New writes a MIME encoded message to w.
func New(
	w io.Writer,
	header Header,
	msg string,
	attachments []*Attachment,
) error {
	writer := multipart.NewWriter(w)
	err := mailHeader(w, header, getSubject(msg), writer.Boundary())
	if err != nil {
		return err
	}
	if err := multipartMIME(writer, msg, attachments); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return log.Error(err)
	}
	return nil
}

// EncodeChunks splits a MIME encoded message msg into multiple chunks of
// given size many bytes.
func EncodeChunks(
	header Header,
	msg string,
	size uint64,
) (chunks []string, err error) {
	msgLen := uint64(len(msg))
	numOfChunks := msgLen / size
	if msgLen%size > 0 {
		numOfChunks++
	}
	var chunk bytes.Buffer
	for i := uint64(0); i < numOfChunks; i++ {
		chunk.Reset()
		writer := multipart.NewWriter(&chunk)
		err := mailHeader(&chunk, header, "", writer.Boundary())
		if err != nil {
			return nil, log.Error(err)
		}

		mh := make(textproto.MIMEHeader)
		mh.Add("Content-Type",
			fmt.Sprintf("chunked; piece=%d; count=%d; chunkid=\"%s\"", i+1,
				numOfChunks, header.MessageID))
		mh.Add("Content-Transfer-Encoding", "base64")
		chunkWriter, err := writer.CreatePart(mh)
		if err != nil {
			return nil, log.Error(err)
		}
		// TODO: take envelope length into consideration for length calculation
		end := (i + 1) * size
		if end > msgLen {
			end = msgLen
		}
		_, err = io.WriteString(chunkWriter, msg[i*size:end])
		if err != nil {
			return nil, log.Error(err)
		}
		if err := writer.Close(); err != nil {
			return nil, log.Error(err)
		}
		chunks = append(chunks, chunk.String())
	}
	return
}

// DecodeChunk decodes the given chunk.
func DecodeChunk(chunk string) (
	header *Header,
	part string,
	piece, count uint64,
	err error,
) {
	var h Header
	msg, err := mail.ReadMessage(bytes.NewBufferString(chunk))
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}

	// parse header
	h.From = msg.Header.Get("From")
	h.To = msg.Header.Get("To")
	if msg.Header.Get("Cc") != "" {
		addressList, err := msg.Header.AddressList("Cc")
		if err != nil {
			return nil, "", 0, 0, log.Error(err)
		}
		for _, address := range addressList {
			h.Cc = append(h.Cc, address.Address)
		}
	}
	h.MessageID = msg.Header.Get("Message-ID")
	h.InReplyTo = msg.Header.Get("In-Reply-To")

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}

	if mediaType != "multipart/mixed" {
		return nil, "", 0, 0,
			log.Errorf("mime: unexpected mediaType: %s", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	p, err := mr.NextPart()
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}

	mediaType, params, err = mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}
	piece, err = strconv.ParseUint(params["piece"], 10, 64)
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}
	count, err = strconv.ParseUint(params["count"], 10, 64)
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}
	if params["chunkid"] != h.MessageID {
		return nil, "", 0, 0, log.Errorf("mime: chunkID differs from messageID")
	}

	slurp, err := ioutil.ReadAll(p)
	if err != nil {
		return nil, "", 0, 0, log.Error(err)
	}
	part = string(slurp)

	header = &h
	return
}

// Parse parses a MIME encoded message.
func Parse(r io.Reader) (
	header *Header,
	subject string,
	message string,
	attachments []*Attachment,
	err error,
) {
	var h Header
	// read message
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	}
	// parse 'From'
	h.From = msg.Header.Get("From")
	if h.From == "" {
		return nil, "", "", nil, log.Error("mime: 'From' not defined")
	}
	// parse 'To'
	h.To = msg.Header.Get("To")
	if h.To == "" {
		return nil, "", "", nil, log.Error("mime: 'To' not defined")
	}
	// parse 'Cc'
	addressList, err := msg.Header.AddressList("Cc")
	if err != nil && err != mail.ErrHeaderNotPresent {
		return nil, "", "", nil, log.Error(err)
	}
	if err != mail.ErrHeaderNotPresent {
		for _, address := range addressList {
			h.Cc = append(h.Cc, address.Address)
		}
	}
	// parse subject
	subj := msg.Header.Get("Subject")
	if subj == "" {
		return nil, "", "", nil, log.Error("mime: 'Subject' not defined")
	}
	dec := new(mime.WordDecoder)
	subject, err = dec.DecodeHeader(subj)
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	}
	// parse 'Message-ID'
	h.MessageID = msg.Header.Get("Message-ID")
	if h.MessageID == "" {
		return nil, "", "", nil, log.Error("mime: 'Message-ID' not defined")
	}
	// parse 'In-Reply-To'
	h.InReplyTo = msg.Header.Get("In-Reply-To")
	// parse 'MIME-Version'
	if msg.Header.Get("MIME-Version") != "1.0" {
		return nil, "", "", nil, log.Error("mime: wrong 'MIME-Version' header")
	}
	// parse 'Content-Type'
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	} else if mediaType != "multipart/mixed" {
		return nil, "", "", nil, log.Error("mime: wrong 'Content-Type' header ")
	}
	// read first MIME part (message)
	mr := multipart.NewReader(msg.Body, params["boundary"])
	p, err := mr.NextPart()
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	}
	// check 'Content-Type'
	if p.Header.Get("Content-Type") != "text/plain" {
		return nil, "", "", nil,
			log.Error("mime: expected 'text/plain' Content-Type")
	}
	// check 'Content-Transfer-Encoding'
	if p.Header.Get("Content-Transfer-Encoding") != "base64" {
		return nil, "", "", nil,
			log.Error("mime: expected 'base64' Content-Transfer-Encoding")
	}
	// read message
	enc, err := ioutil.ReadAll(p)
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	}
	content, err := base64.Decode(string(enc))
	if err != nil {
		return nil, "", "", nil, log.Error(err)
	}
	message = string(content)
	// read optional additional MIME parts (attachments)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		// parse header
		contentType := p.Header.Get("Content-Type")
		if contentType == "" {
			return nil, "", "", nil,
				log.Error("mime: Content-Type undefined for attachment")
		}
		var filename string
		var inline bool
		for _, disposition := range p.Header["Content-Disposition"] {
			mediaType, params, err := mime.ParseMediaType(disposition)
			if err != nil {
				return nil, "", "", nil, log.Error(err)
			}
			switch mediaType {
			case "attachment":
				filename = params["filename"]
			case "inline":
				inline = true
			default:
				return nil, "", "", nil,
					log.Errorf("mime: unknown Content-Disposition in attachment: %s",
						mediaType)
			}
		}
		if filename == "" {
			log.Error("mime: filename undefined for attachment")
		}

		// parse body
		if err != nil {
			return nil, "", "", nil, log.Error(err)
		}
		enc, err := ioutil.ReadAll(p)
		if err != nil {
			return nil, "", "", nil, log.Error(err)
		}
		content, err := base64.Decode(string(enc))
		if err != nil {
			return nil, "", "", nil, log.Error(err)
		}
		// reconstruct attachment
		attachment := &Attachment{
			Filename:    filename,
			Reader:      bytes.NewBuffer(content),
			ContentType: contentType,
			Inline:      inline,
		}
		attachments = append(attachments, attachment)
	}

	header = &h
	return
}
