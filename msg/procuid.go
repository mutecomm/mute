package msg

import (
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/uid"
)

type procUIDResult struct {
	uidIndex []byte
	msg      *uid.Message
	err      error
}

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