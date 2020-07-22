// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encode

// ToUint64 converts the byte slice b of length 8 to an uint64.
// If b does not have length 8 the function panics.
func ToUint64(b []byte) (u uint64) {
	if len(b) != 8 {
		panic("encode: ToUint64(): len(b) != 8")
	}
	u = uint64(b[7])<<56 |
		uint64(b[6])<<48 |
		uint64(b[5])<<40 |
		uint64(b[4])<<32 |
		uint64(b[3])<<24 |
		uint64(b[2])<<16 |
		uint64(b[1])<<8 |
		uint64(b[0])
	return
}

// ToUint16 converts the byte slice b of length 2 to an uint16.
// If b does not have length 2 the function panics.
func ToUint16(b []byte) (u uint16) {
	if len(b) != 2 {
		panic("encode: ToUint16(): len(b) != 2")
	}
	u = uint16(b[1])<<8 |
		uint16(b[0])
	return
}

// ToByte8 converts the uint64 u to a byte slice of length 8.
func ToByte8(u uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(u)
	b[1] = byte(u >> 8)
	b[2] = byte(u >> 16)
	b[3] = byte(u >> 24)
	b[4] = byte(u >> 32)
	b[5] = byte(u >> 40)
	b[6] = byte(u >> 48)
	b[7] = byte(u >> 56)
	return b
}

// ToByte2 converts the uint16 u to a byte slice of length 2.
func ToByte2(u uint16) []byte {
	b := make([]byte, 2)
	b[0] = byte(u)
	b[1] = byte(u >> 8)
	return b
}

// ToByte1 converts the uint8 u to a byte slice of length 1.
func ToByte1(u uint8) []byte {
	b := make([]byte, 1)
	b[0] = byte(u)
	return b
}
