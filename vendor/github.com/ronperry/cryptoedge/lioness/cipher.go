// Package lioness implements the LIONESS Large Block Cipher with some modifications:
// Instead of using a standard stream cipher, it only allows usage of block ciphers that
// implement the cipher.Block interface.
// Furthermore it does not use the suggested hash operation but instead uses an HMAC everywhere a hash is used
// in the original design
// Paper: http://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
// In addition, this implementation supports two modes. ModeZero, which uses an all zero IV for the R-operation, and
// ModeIV, which uses the content of L as the IV.
package lioness

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

const (
	// ModeIV uses L as the IV for encryption
	ModeIV = iota
	// ModeZero uses all zeros as the IV for encryption
	ModeZero
)

// Lioness holds internal data
type Lioness struct {
	blockcipher    func([]byte) (cipher.Block, error)
	hash           func() hash.Hash
	keylen         int
	blocksize      int // blocksize of cipher
	mode           int
	k1, k2, k3, k4 []byte
}

var (
	// ErrConstructed is returned if working with a lioness that hasn't been set up
	ErrConstructed = errors.New("lioness: Missing setup")
	// ErrKeyHashSize is returned if the key size is larger than the hash size
	ErrKeyHashSize = errors.New("lioness: Hash smaller than key")
	// ErrKeyLen is returned when the keys given do not match the key length
	ErrKeyLen = errors.New("lioness: Keys have wrong size")
	// ErrDataSize is returned when the data is too small (<=keylen)
	ErrDataSize = errors.New("lioness: Not enough data")
	// ErrNoKeys is returned if using a lioness without keys
	ErrNoKeys = errors.New("lioness: Keys not set")
)

var zeroIV []byte

// Construct returns a new Lioness. Takes block cipher, hash function and keylen. Key can be nil. mode is either ModeIV or ModeZero
func Construct(blockcipher func([]byte) (cipher.Block, error), hash func() hash.Hash, keylen int, key []byte, mode int) (*Lioness, error) {
	h := hash()
	if h.Size() < keylen {
		return nil, ErrKeyHashSize
	}
	algo, err := blockcipher(make([]byte, keylen))
	if err != nil {
		return nil, err
	}
	t := new(Lioness)
	t.blockcipher = blockcipher
	t.blocksize = algo.BlockSize()
	t.hash = hash
	t.keylen = keylen
	t.mode = mode
	if key != nil {
		err := t.ExplodeKey(key)
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// New is shorthand for Construct with aes256 and sha256 in ModeZero
func New(key []byte) (*Lioness, error) {
	return Construct(aes.NewCipher, sha256.New, 32, key, ModeZero)
}

// Setkeys sets the keys and verifies that they are of keylen length
func (l *Lioness) Setkeys(k1, k2, k3, k4 []byte) error {
	if !l.isConstructed() {
		return ErrConstructed
	}
	if len(k1) != l.keylen || len(k2) != l.keylen || len(k3) != l.keylen || len(k4) != l.keylen {
		return ErrKeyLen
	}
	l.k1, l.k2, l.k3, l.k4 = k1, k2, k3, k4
	return nil
}

// ExplodeKey generates the Lioness keys from a single input key by calculating repeated HMACs (which is of questionable security)
func (l *Lioness) ExplodeKey(key []byte) error {
	if !l.isConstructed() {
		return ErrConstructed
	}
	l.k1 = l.ropHMAC(key, append(key, key...))[0:l.keylen]
	l.k2 = l.ropHMAC(key, append(l.k1, key...))[0:l.keylen]
	l.k3 = l.ropHMAC(key, append(l.k2, key...))[0:l.keylen]
	l.k4 = l.ropHMAC(key, append(l.k3, key...))[0:l.keylen]
	return nil
}

// Encrypt the data, return error if too little data is given
func (l *Lioness) Encrypt(data []byte) ([]byte, error) {
	if !l.isConstructed() {
		return nil, ErrConstructed
	}
	if !l.hasKeys() {
		return nil, ErrNoKeys
	}
	if len(data) < l.keylen+1 {
		return nil, ErrDataSize
	}
	L := data[:l.keylen]
	R := data[l.keylen:]
	R, err := l.rop(l.getIV(L), l.ropHMAC(l.k1, L), R)
	if err != nil {
		return nil, err
	}
	L = l.xor(L, l.ropHMAC(R, l.k2))
	R, err = l.rop(l.getIV(L), l.ropHMAC(l.k3, L), R)
	if err != nil {
		return nil, err
	}
	L = l.xor(L, l.ropHMAC(R, l.k4))
	return append(L, R...), nil
}

// Decrypt the data, return error if too little data is given
func (l *Lioness) Decrypt(data []byte) ([]byte, error) {
	if !l.isConstructed() {
		return nil, ErrConstructed
	}
	if !l.hasKeys() {
		return nil, ErrNoKeys
	}
	if len(data) < l.keylen+1 {
		return nil, ErrDataSize
	}
	L := data[:l.keylen]
	R := data[l.keylen:]
	L = l.xor(L, l.ropHMAC(R, l.k4))
	R, err := l.rop(l.getIV(L), l.ropHMAC(l.k3, L), R)
	if err != nil {
		return nil, err
	}

	L = l.xor(L, l.ropHMAC(R, l.k2))
	R, err = l.rop(l.getIV(L), l.ropHMAC(l.k1, L), R)
	if err != nil {
		return nil, err
	}
	return append(L, R...), nil
}

// getIV returns the IV depending on mode
func (l *Lioness) getIV(L []byte) []byte {
	if l.mode == ModeZero {
		if zeroIV == nil {
			zeroIV = make([]byte, l.blocksize)
		}
		return zeroIV
	}
	return L[:l.blocksize]
}

// isConstructed verifies that the lioness has been constructed. To create more meaningful errors
func (l *Lioness) isConstructed() bool {
	if l == nil {
		return false
	}
	if l.keylen < 1 {
		return false
	}
	return true
}

// hasKeys verifies that the lioness has keys. To create more meaningful errors
func (l *Lioness) hasKeys() bool {
	if len(l.k1) != l.keylen || len(l.k2) != l.keylen || len(l.k3) != l.keylen || len(l.k4) != l.keylen {
		return false
	}
	return true
}

// Rop implements the R operation, encrypting with stream cipher
func (l *Lioness) rop(iv, key, plaintext []byte) (ciphertext []byte, err error) {
	algo, err := l.blockcipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext = make([]byte, len(plaintext))
	stream := cipher.NewCTR(algo, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// RopHMAC generates the hmac of R for the L operation
func (l *Lioness) ropHMAC(key, data []byte) []byte {
	mac := hmac.New(l.hash, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Xor two byte slices a and b. Extra input bytes are dropped. Extra output bytes over keylen are dropped
func (l *Lioness) xor(a, b []byte) []byte {
	x, y := a, b
	if len(a) < len(b) {
		x, y = b, a
	}
	t := make([]byte, len(y))
	for i := 0; i < len(y); i++ {
		t[i] = x[i] ^ y[i]
	}
	if len(y) > l.keylen {
		return t[:l.keylen]
	}
	return t
}
