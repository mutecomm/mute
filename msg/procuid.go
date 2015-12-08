// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg

import (
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/uid"
)

type procUIDResult struct {
	uidIndex []byte       // UIDIndex = SHA256(SHA256(UIDMessage))
	msg      *uid.Message // decoded UID message
	err      error
}

// procUID allows to process a sender UID from the header in parallel.
// senderUID is the JSON encoded UID message parsed from the header, res is
// the result channel used to communicate the result of the calculation.
func procUID(senderUID string, res chan *procUIDResult) {
	var r procUIDResult
	var err error
	r.uidIndex = cipher.SHA256(cipher.SHA256([]byte(senderUID)))
	r.msg, err = uid.NewJSON(senderUID)
	if err != nil {
		res <- &procUIDResult{uidIndex: nil, msg: nil, err: err}
		return
	}
	// return results
	res <- &r
}
