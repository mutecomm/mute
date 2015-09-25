// Package client implements client functionality for the Mute mix system.
package client

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/mail"
	"strings"
	"time"
)

// ReadMail reads an email and returns the decoded body.
func ReadMail(message []byte) (body []byte, err error) {
	pm, err := mail.ReadMessage(bytes.NewBuffer(message))
	if err != nil {
		return nil, err
	}
	mbody := make([]byte, MaxMessageSize+1)
	n, _ := io.ReadFull(pm.Body, mbody)
	if n > MaxMessageSize {
		return nil, ErrMaxSize
	}
	return base64.StdEncoding.DecodeString(string(mbody[0:n]))
}

// WriteMail writes an encoded mail.
func WriteMail(sender, receiver string, body []byte) (mail []byte) {
	header := "From: " + sender + "\r\nTo: " + receiver + "\r\n" +
		"Subject: Mix message\r\nContent-Type: text/text\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/base64; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n\r\n"
	return []byte(header + splitMaxLine(base64.StdEncoding.EncodeToString(body), 72))
}

func splitMaxLine(inStr string, width int) string {
	var out []string
	inStrL := len(inStr)
	if inStrL <= width {
		return inStr
	}
	for i := 0; i < inStrL; i += width {
		if (i + width) >= inStrL {
			out = append(out, inStr[i:])
			break
		}
		out = append(out, inStr[i:i+width])
	}
	return strings.Join(out, "\r\n")
}
