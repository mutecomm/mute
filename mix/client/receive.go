// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/walletauth"
	"github.com/mutecomm/mute/util/times"
)

// FetchMessage fetches a message from the accountserver.
func FetchMessage(privkey *[ed25519.PrivateKeySize]byte, messageID []byte, server string, cacert []byte) ([]byte, error) {
	var authtoken []byte
	var err error
	var message []byte
	lastcounter := uint64(times.NowNano())
	pubkey := splitKey(privkey)
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		if authtoken == nil {
			authtoken = walletauth.CreateToken(pubkey, privkey, lastcounter+1)
		}
		message, lastcounter, err = fetchmessage(messageID, authtoken, server, cacert)
		if err == walletauth.ErrReplay {
			authtoken = nil
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		break CallLoop
	}
	return message, err

}

func fetchmessage(messageID, authtoken []byte, server string, cacert []byte) (message []byte, lastcounter uint64, err error) {
	postVal := url.Values{}
	postVal.Set("messageid", hex.EncodeToString(messageID))
	postVal.Set("authtoken", base64.StdEncoding.EncodeToString(authtoken))
	body, err := HTTPSPost(postVal, "https://"+server+":"+RPCPort+"/message", cacert)
	if err != nil {
		return nil, 0, err
	}
	if len(body) < 7 {
		return nil, 0, ErrProto
	}
	if string(body[0:6]) == "ERROR:" {
		errStr := body[7:]
		err := fmt.Errorf("%s", errStr)
		LastCounter, err := walletauth.IsReplay(err)
		return nil, LastCounter, err
	}
	message, err = ReadMail(body)
	if err != nil {
		return nil, 0, err
	}
	return message, 0, nil
}
