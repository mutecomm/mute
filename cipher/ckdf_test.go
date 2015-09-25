package cipher

import (
	"encoding/hex"
	"testing"

	"github.com/mutecomm/mute/encode"
)

const (
	k1Res = "c636aaedf55022224b6785e329453a561c66e52add44fb36a0327c67ecb33ac8cf552223d041f964795d7987fe8beb09bb2aa103d148ad98b7eb0c9f87d49b8c"
	k2Res = "9f6d3daa0612e82585ea90080355ef083cc16809abe0d0303882cac55c587dcb8088a422c6daf4037225c400c3261ea914526a0f679a6fd7997241691eef2bfc"
)

func TestCKDF(t *testing.T) {
	k1, k2 := CKDF(encode.ToByte8(0))
	k1Hex := hex.EncodeToString(k1)
	if k1Hex != k1Res {
		t.Errorf("k1 == \"%s\" != \"%s\")", k1Hex, k1Res)
	}
	k2Hex := hex.EncodeToString(k2)
	if k2Hex != k2Res {
		t.Errorf("k2 == \"%s\" != \"%s\")", k2Hex, k2Res)
	}
}
