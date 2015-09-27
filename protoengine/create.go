// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protoengine

import (
	"io"
	"io/ioutil"

	"github.com/mutecomm/mute/def"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/mix/client"
)

func (pe *ProtoEngine) create(
	w io.Writer,
	minDelay, maxDelay int32,
	tokenString, nymaddress string,
	r io.Reader,
) error {
	msg, err := ioutil.ReadAll(r)
	if err != nil {
		return log.Error(err)
	}
	message, err := base64.Decode(string(msg))
	if err != nil {
		return log.Error(err)
	}
	token, err := base64.Decode(tokenString)
	if err != nil {
		return log.Error(err)
	}
	na, err := base64.Decode(nymaddress)
	if err != nil {
		return log.Error(err)
	}
	mo := client.MessageInput{
		SenderMinDelay: minDelay,
		SenderMaxDelay: maxDelay,
		Token:          token,
		NymAddress:     na,
		Message:        message,
		SMTPPort:       2025,                          // TODO: allow to set SMTPPort
		SmartHost:      "mix.serviceguard.chavpn.net", // TODO: allow to set SmartHost
		CACert:         def.CACert,
	}.Create()
	if mo.Error != nil {
		return log.Error(mo.Error)
	}
	envelope := mo.Marshal()
	if _, err := io.WriteString(w, base64.Encode(envelope)); err != nil {
		return log.Error(err)
	}
	return nil
}
