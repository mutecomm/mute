package hashchain

import (
	"bytes"
	"testing"
)

const entry = "PxIx7lxwcKB3vmPLGzqm3alBCBkHbD89qRBWs7+N8yMB6QEQSe7yf4BrMISdYWeF/Ycm7tKzb6q8LZgdjtTHHAFSkuD/Q3aUITVhT19g5WKwEZ1TlMH0n7ymEEVVhW/PtEDOO/uMoEOKTTvwQp6QA2NE1GYYqhzBtQNHawFtw5NUnupGnDV+QqpJrSUoe/vkXnWZfDiY9Q1W"

func TestSplitEntry(t *testing.T) {
	_, typ, _, _, _, _, err := SplitEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(typ, []byte{0x01}) {
		t.Error("typ != 0x01")
	}
}
