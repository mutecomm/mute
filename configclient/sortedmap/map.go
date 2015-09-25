// Package sortedmap implements sorted and signed maps.
package sortedmap

import (
	"crypto/sha512"
	"encoding/binary"
	"sort"

	"github.com/agl/ed25519"
)

// StringMap is a string->string map.
type StringMap map[string]string

// StringStruct is a stringmap converted to struct.
type StringStruct struct {
	K, V string
}

// SortedMap is a sorted (or sortable) string->string representation.
type SortedMap []StringStruct

// ToMap returns a standard map from a SortedMap
func (so SortedMap) ToMap() StringMap {
	r := make(StringMap)
	for _, e := range so {
		r[e.K] = e.V
	}
	return r
}

// Sort converts a StingMap into a SortedMap.
func (sm StringMap) Sort() SortedMap {
	r := make(SortedMap, len(sm))
	i := 0
	for k, v := range sm {
		r[i] = StringStruct{
			K: k,
			V: v,
		}
		i++
	}
	sort.Sort(r)
	return r
}

// Len returns the number of elements in the SortedMap.
// sort.Sort interface implementation.
func (so SortedMap) Len() int {
	return len(so)
}

// Swap swaps two elements in the SortedMap. sort.Sort interface implementation.
func (so SortedMap) Swap(i, j int) {
	so[i], so[j] = so[j], so[i]
}

// Less compares i and j from SortedMap. sort.Sort interface implementation.
func (so SortedMap) Less(i, j int) bool {
	return so[i].K < so[j].K
}

// lenByte converts a string into a byte slice that also contains the length
// of the string.
func lenByte(d string) []byte {
	l := len(d)
	r := make([]byte, l+8)
	binary.BigEndian.PutUint64(r[0:8], uint64(l))
	copy(r[8:], d)
	return r
}

// Image returns the sha512 hash of SortedMap
func (so SortedMap) Image() []byte {
	var err error
	h := sha512.New()
	length := 0
	for _, e := range so {
		d1 := lenByte(e.K)
		d2 := lenByte(e.V)
		length = length + len(d1) + len(d2)
		_, err = h.Write(d1)
		if err != nil {
			panic(err.Error())
		}
		_, err = h.Write(d2)
		if err != nil {
			panic(err.Error())
		}
	}
	l := make([]byte, 8)
	binary.BigEndian.PutUint64(l, uint64(length))
	_, err = h.Write(l)
	if err != nil {
		panic(err.Error())
	}
	return h.Sum(make([]byte, 0))
}

// Sign a SortedMap with the given private key, returns the signature.
func (so SortedMap) Sign(signdate uint64, privKey *[ed25519.PrivateKeySize]byte) []byte {
	sdate := make([]byte, 8)
	binary.BigEndian.PutUint64(sdate, signdate)
	sig := ed25519.Sign(privKey, append(so.Image(), sdate...))
	return sig[:]
}

// Verify a signature for a SortedMap with the publickey.
func (so SortedMap) Verify(signdate uint64, publicKey []byte, signature []byte) bool {
	var pubkey [ed25519.PublicKeySize]byte
	var sig [ed25519.SignatureSize]byte
	sdate := make([]byte, 8)
	binary.BigEndian.PutUint64(sdate, signdate)

	copy(pubkey[:], publicKey)
	copy(sig[:], signature)
	return ed25519.Verify(&pubkey, append(so.Image(), sdate...), &sig)
}
