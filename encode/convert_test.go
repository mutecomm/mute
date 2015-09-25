package encode

import "testing"

func TestToUint64(t *testing.T) {
	b := make([]byte, 8)
	if ToUint64(b) != 0 {
		t.Error("ToUint64(b) != 0")
	}
	b[1] = 0x1
	if ToUint64(b) != 256 {
		t.Error("ToUint64(b) != 256")
	}
	b[1] = 0x2
	if ToUint64(b) != 512 {
		t.Error("ToUint64(b) != 512")
	}
	b[2] = 0x1
	if ToUint64(b) != 66048 {
		t.Error("ToUint64(b) != 66048")
	}

	b = make([]byte, 7)
	defer func() {
		if r := recover(); r == nil {
			t.Error("ToUint64(b) with len(b) != 8 is supposed to panic")
		}
	}()
	ToUint64(b)
}

func TestToUint16(t *testing.T) {
	b := make([]byte, 2)
	if ToUint16(b) != 0 {
		t.Error("ToUint16(b) != 0")
	}
	b[1] = 0x1
	if ToUint16(b) != 256 {
		t.Error("ToUint16(b) != 256")
	}
	b[1] = 0x2
	if ToUint16(b) != 512 {
		t.Error("ToUint16(b) != 512")
	}

	b = make([]byte, 3)
	defer func() {
		if r := recover(); r == nil {
			t.Error("ToUint16(b) with len(b) != 2 is supposed to panic")
		}
	}()
	ToUint16(b)
}

func TestToByte8(t *testing.T) {
	b := ToByte8(255)
	if b[0] != 0xff {
		t.Error("b[0] != 0xff")
	}
	b = ToByte8(256)
	if b[0] != 0x0 {
		t.Error("b[0] != 0x0")
	}
	if b[1] != 0x1 {
		t.Error("b[1] != 0x1")
	}
}

func TestToByte2(t *testing.T) {
	b := ToByte2(255)
	if b[0] != 0xff {
		t.Error("b[0] != 0xff")
	}
	b = ToByte2(256)
	if b[0] != 0x0 {
		t.Error("b[0] != 0x0")
	}
	if b[1] != 0x1 {
		t.Error("b[1] != 0x1")
	}
}

func TestToByte1(t *testing.T) {
	b := ToByte1(255)
	if b[0] != 0xff {
		t.Error("b[0] != 0xff")
	}
	b = ToByte1(1)
	if b[0] != 0x1 {
		t.Error("b[0] != 0x1")
	}
}
