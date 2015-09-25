package base64

import (
	"bytes"
	"io/ioutil"
	"testing"
)

const (
	data = "5WBIS6whUU/Zuo9o0hqawcHAv8SZcxd9NzA79tEUcCI="
)

func TestBase64Function(t *testing.T) {
	dec, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if data != Encode(dec) {
		t.Fatal("encodings differ")
	}
}

func TestBase64Coder(t *testing.T) {
	r := NewDecoder(bytes.NewBufferString(data))
	dec, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	encoder := NewEncoder(&buf)
	if _, err := encoder.Write(dec); err != nil {
		t.Fatal(err)
	}
	encoder.Close()
	if data != buf.String() {
		t.Fatal("encodings differ")
	}
}
