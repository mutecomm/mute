// Package eccutil contains various utility functions to implement protocols over ecc
package eccutil

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"io"
	"math/big"
)

// MaxLoopCount is the maximum number of tries we do for parameter search
const MaxLoopCount = 1000

// Point describes a point on a curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// Curve encapsulates an elliptic curve
type Curve struct {
	Curve  elliptic.Curve
	Rand   io.Reader
	Params *elliptic.CurveParams
	Nminus *big.Int
	Hash   func([]byte) []byte
}

var (
	// ErrMsgShort is returned when the message is too short
	ErrMsgShort = errors.New("singhdas: Message too short")
	// ErrBadCoordinate is returned if a coordinate is an illegal value
	ErrBadCoordinate = errors.New("singhdas: Coordinate illegal value")
	// ErrCoordinateBase is returned if a coordinate is in the base point
	ErrCoordinateBase = errors.New("singhdas: Coordinate illegal value (basepoint,reflection,inverse)")
	// ErrMaxLoop is returned if we cannot find parameters in time, should only happen during testing
	ErrMaxLoop = errors.New("singhdas: Cannot find parameters")
	// ErrNotRelPrime is returned if two numbers must be relative prime but are not
	ErrNotRelPrime = errors.New("singhdas: Not relative prime")
	// ErrParamReuse is returned if blinding parameters are used again
	ErrParamReuse = errors.New("singhdas: Do not reuse blinding parameters")
	// ErrBadBlindParam is returned if the blinding parameter is unusable
	ErrBadBlindParam = errors.New("singhdas: Blinding parameter unusable")
	// ErrHashDif is returned if the hash of the message diffs from the signature
	ErrHashDif = errors.New("singhdas: Hash does not match signature")
	// ErrSigWrong is returned if the signature does not verify for the message and public key of signer
	ErrSigWrong = errors.New("singhdas: Signature does not verify")
)

var (
	// TestZero testing shortcut variable
	TestZero = big.NewInt(0)
	// TestOne testing shortcut variable
	TestOne = big.NewInt(1)
	// TestTwo testing shortcut variable
	TestTwo = big.NewInt(2)
)

// Packaging: GetCoords, SetCoords

// GetCoordinates returns the coordinates of a point
func (p *Point) GetCoordinates() (x, y *big.Int) {
	return p.X, p.Y
}

// NewPoint returns a *Point with x,y coordinates
func NewPoint(x, y *big.Int) (p *Point) {
	p = new(Point)
	p.X, p.Y = x, y
	return p
}

// ZeroPoint returns a point with (0,0)
func ZeroPoint() *Point {
	p := new(Point)
	p.X, p.Y = big.NewInt(0), big.NewInt(0)
	return p
}

// SetCurve returns a Curve encapsulating the curve given
func SetCurve(curve func() elliptic.Curve, rand io.Reader, hash func([]byte) []byte) *Curve {
	c := new(Curve)
	c.Curve = curve()
	c.Rand = rand
	c.Params = c.Curve.Params()
	c.Hash = hash
	c.Nminus = new(big.Int)
	c.Nminus = c.Nminus.Sub(c.Params.N, TestOne)
	return c
}

// GenerateKey returns a new keypair
func (curve Curve) GenerateKey() (priv []byte, pub *Point, err error) {
	priv, x, y, err := elliptic.GenerateKey(curve.Curve, curve.Rand)
	if err != nil {
		return nil, nil, err
	}
	pub = new(Point)
	pub.X, pub.Y = x, y
	return priv, pub, nil
}

// TestCoordinate verifies that a number is not the  coordinate of the base point of the curve nor
// that it is zero or one
func (curve Curve) TestCoordinate(i *big.Int) (bool, error) {
	if i.Cmp(TestZero) == 0 {
		return false, ErrBadCoordinate
	}
	if i.Cmp(TestOne) == 0 {
		return false, ErrBadCoordinate
	}
	return true, nil
}

// ModInverse calculates the modular inverse of a over P
func (curve Curve) ModInverse(a *big.Int) (*big.Int, error) {
	// since P should be a prime, any GCD calculation is really a waste if a != P
	if a.Cmp(curve.Params.N) == 0 {
		return nil, ErrNotRelPrime
	}
	if a.Cmp(big.NewInt(1)) == 0 { // this should never happen
		return nil, ErrNotRelPrime
	}
	if a.Cmp(big.NewInt(0)) == 0 { // this should never happen
		return nil, ErrNotRelPrime
	}
	z := new(big.Int)
	z = z.GCD(nil, nil, a, curve.Params.N)
	if z.Cmp(big.NewInt(1)) == 0 {
		z = z.ModInverse(a, curve.Params.N)
		return z, nil
	}
	return nil, ErrNotRelPrime
}

// TestInverse verifies that a number is the multiplicative inverse over P of another number
func (curve Curve) TestInverse(a, b *big.Int) bool {
	z := new(big.Int)
	z = z.Mul(a, b)
	z = z.Mod(z, curve.Params.N)
	if z.Cmp(big.NewInt(1)) == 0 {
		return true
	}
	return false
}

// TestPoint verifies that a point (x1,y2) does not equal another point (x1,y2) or it's reflection on 0
func (curve Curve) TestPoint(x1, y1, x2, y2 *big.Int) (bool, error) {
	_, err := curve.TestCoordinate(x1)
	if err != nil {
		return false, err
	}
	_, err = curve.TestCoordinate(x2)
	if err != nil {
		return false, err
	}
	if x1.Cmp(x1) == 0 && y1.Cmp(y2) == 0 { // Same
		return false, ErrCoordinateBase
	}
	if x1.Cmp(y1) == 0 && y1.Cmp(x2) == 0 { // Reflect
		return false, ErrCoordinateBase
	}
	x2neg := new(big.Int)
	x2neg = x2neg.Neg(x2)
	y2neg := new(big.Int)
	y2neg = y2neg.Neg(y2)
	if x1.Cmp(x2neg) == 0 {
		return false, ErrCoordinateBase
	}
	if x1.Cmp(y2neg) == 0 && y1.Cmp(x2neg) == 0 {
		return false, ErrCoordinateBase
	}
	return true, nil
}

// TestParams runs tests on parameters to make sure they do not form a dangerous combination
func (curve Curve) TestParams(a ...*big.Int) (bool, error) {
	// Simple tests first
	for _, y := range a {
		if y.Cmp(TestZero) == 0 { // 0 is unacceptable
			return false, ErrBadCoordinate
		}
		if y.Cmp(TestOne) == 0 { // 1 is unacceptable
			return false, ErrBadCoordinate
		}
		if y.Cmp(curve.Params.P) == 0 { // Cannot be the mod
			return false, ErrBadCoordinate
		}
		if y.Cmp(curve.Params.N) == 0 { // Cannot be the order
			return false, ErrBadCoordinate
		}
		if y.Cmp(curve.Params.Gx) == 0 { // cannot be the generator point
			return false, ErrBadCoordinate
		}
	}
	// Test duplicates and inverses
	for i := 0; i < len(a)-1; i++ {
		for j := i + 1; j < len(a); j++ {
			if a[i].Cmp(a[j]) == 0 {
				return false, ErrBadCoordinate
			}
			if curve.TestInverse(a[i], a[j]) {
				return false, ErrBadCoordinate
			}

		}
	}
	return true, nil
}

// ExtractR extracts the x coordinate of a point and tests it for validity
func (curve Curve) ExtractR(p *Point) (*big.Int, error) {
	r := new(big.Int)
	r = r.Mod(p.X, curve.Params.N)                   // This should be unnecessary since the scalarmult has taken care of it
	if r.Cmp(TestZero) == 0 || r.Cmp(TestOne) == 0 { // Genkey should have taken care of this
		return nil, ErrBadCoordinate
	}
	return r, nil
}

// BytesToInt is a helper function to convert bytes into Int the quick way
func BytesToInt(b []byte) *big.Int {
	z := new(big.Int)
	z = z.SetBytes(b)
	return z
}

// ManyMult multiplies all parameters
func ManyMult(a ...*big.Int) *big.Int {
	if len(a) == 1 {
		return a[0]
	}
	z := big.NewInt(1)
	if len(a) == 2 {
		return z.Mul(a[0], a[1])
	}
	for _, y := range a {
		z = z.Mul(z, y)
	}
	return z
}

// ManyAdd multiplies all parameters
func ManyAdd(a ...*big.Int) *big.Int {
	if len(a) == 1 {
		return a[0]
	}
	z := big.NewInt(1)
	if len(a) == 2 {
		return z.Add(a[0], a[1])
	}
	for _, y := range a {
		z = z.Add(z, y)
	}
	return z
}

// RandomElement returns a random element within (1,N-1)
func (curve Curve) RandomElement() (*big.Int, error) {
	for {
		i, err := rand.Int(curve.Rand, curve.Nminus)
		if err != nil {
			return nil, err
		}
		if i.Cmp(TestOne) == 1 {
			return i, nil
		}
	}
}

// AddPoints adds two points and returns the result
func (curve Curve) AddPoints(a, b *Point) *Point {
	r := new(Point)
	r.X, r.Y = curve.Curve.Add(a.X, a.Y, b.X, b.Y)
	return r
}

// Mod returns a % curve.N
func (curve Curve) Mod(a *big.Int) *big.Int {
	b := new(big.Int)
	b = b.Mod(a, curve.Params.N)
	return b
}

// ScalarMult returns the result of a scalar multiplication
func (curve Curve) ScalarMult(p *Point, k []byte) *Point {
	r := new(Point)
	r.X, r.Y = curve.Curve.ScalarMult(p.X, p.Y, k)
	return r
}

// ScalarBaseMult returns the result of a scalar multiplication
func (curve Curve) ScalarBaseMult(k []byte) *Point {
	r := new(Point)
	r.X, r.Y = curve.Curve.ScalarBaseMult(k)
	return r
}

// WithinRange tests if a number is in the field defined by curve.N
func (curve Curve) WithinRange(i *big.Int) bool {
	if i.Cmp(TestOne) != 1 && i.Cmp(curve.Nminus) != -1 {
		return false
	}
	return true
}

// GenHash returns the hash of msg as Int
func (curve Curve) GenHash(msg []byte) *big.Int {
	// Make dependent on BitSize
	x := new(big.Int)
	x = x.SetBytes(curve.Hash(msg))
	return x
}

// Sha1Hash is an example hash function doing sha1 over []byte and returning []byte
func Sha1Hash(b []byte) []byte {
	x := sha1.Sum(b)
	return x[:]
}

// GenNV generates the signature blind/nonce. Copied from src/crypto/elliptic/elliptic.go GenerateKey
func (curve Curve) GenNV() (nv []byte, err error) {
	var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}
	var x *big.Int
	var loopcount int
	bitSize := curve.Curve.Params().BitSize
	byteLen := (bitSize + 7) >> 3
	nv = make([]byte, byteLen)
	for x == nil {
		if loopcount > MaxLoopCount {
			return nil, ErrMaxLoop
		}
		loopcount++
		_, err = io.ReadFull(curve.Rand, nv)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		nv[0] &= mask[bitSize%8]
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		nv[1] ^= 0x42
		x, _ = curve.Curve.ScalarBaseMult(nv)
		if x.Cmp(big.NewInt(0)) == 0 { // This cannot really happen ever
			x = nil
		}
	}
	return
}

// GenNVint returns an int from genNV
func (curve Curve) GenNVint() (nvi *big.Int, err error) {
	nv, err := curve.GenNV()
	if err != nil {
		return nil, err
	}
	nvi = new(big.Int)
	nvi = nvi.SetBytes(nv)
	return nvi, nil
}

// PointEqual returns true if the points a and b are the same
func PointEqual(a, b *Point) bool {
	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		return true
	}
	return false
}
