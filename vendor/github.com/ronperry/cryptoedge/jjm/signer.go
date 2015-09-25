package jjm

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// Signer is a single signer
type Signer struct {
	curve   *eccutil.Curve
	privkey []byte
	pubkey  *eccutil.Point
}

// SignRequestPublicInt are the public parameters given to a signature requestor
type SignRequestPublicInt struct {
	PointRs1, PointRs2   *eccutil.Point // R points
	ScalarLs1, ScalarLs2 *big.Int       // l parameters
}

// SignRequestPrivateInt are the _private_ parameters for the operation, never to be released
type SignRequestPrivateInt struct {
	ScalarKs1, ScalarKs2 *big.Int       // k parameters. Private.  kn x curve.G == Rn
	PointRs1, PointRs2   *eccutil.Point // R points. Public data, but kept for reverence
	ScalarLs1, ScalarLs2 *big.Int       // l parameters. Public data, but kept for reverence
	ScalarRs1, ScalarRs2 *big.Int       // x coordinates of PointRs1, PointRs2. Public. Pre-calculated.
	IsUsed               bool
}

// BlindSignatureInt is a blind signature
type BlindSignatureInt struct {
	ScalarS1, ScalarS2 *big.Int
}

// NewSigner returns a new Signer instance
func NewSigner(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve) *Signer {
	s := new(Signer)
	s.curve = curve
	s.privkey = privkey
	s.pubkey = pubkey
	return s
}

// NewSignRequest creates a new signature request parameter set.
// Public is given to requestor, Private is kept for later signature
func (signer *Signer) NewSignRequest() (Public *SignRequestPublicInt, Private *SignRequestPrivateInt, err error) {
	var loopcount int
	for {
		if loopcount > eccutil.MaxLoopCount {
			return nil, nil, eccutil.ErrMaxLoop
		}
		loopcount++
		ScalarKs1B, PointRs1, err := signer.curve.GenerateKey()
		if err != nil {
			continue
		}
		ScalarKs2B, PointRs2, err := signer.curve.GenerateKey()
		if err != nil {
			continue
		}
		ScalarRs1, err := signer.curve.ExtractR(PointRs1)
		if err != nil {
			continue
		}
		ScalarRs2, err := signer.curve.ExtractR(PointRs2)
		if err != nil {
			continue
		}

		ScalarLs1, err := signer.curve.GenNVint() // this limits L substantially, and might not be the best idea
		if err != nil {
			continue
		}
		ScalarLs2, err := signer.curve.GenNVint() // this limits L substantially, and might not be the best idea
		if err != nil {
			continue
		}

		tPrivate := new(SignRequestPrivateInt)
		tPrivate.PointRs1 = PointRs1
		tPrivate.PointRs2 = PointRs2
		tPrivate.ScalarKs1 = new(big.Int)
		tPrivate.ScalarKs1 = tPrivate.ScalarKs1.SetBytes(ScalarKs1B)
		tPrivate.ScalarKs2 = new(big.Int)
		tPrivate.ScalarKs2 = tPrivate.ScalarKs2.SetBytes(ScalarKs2B)
		tPrivate.ScalarLs1 = ScalarLs1
		tPrivate.ScalarLs2 = ScalarLs2
		tPrivate.ScalarRs1 = ScalarRs1
		tPrivate.ScalarRs2 = ScalarRs2
		tPrivate.IsUsed = false
		_, err = signer.curve.TestParams(tPrivate.ScalarKs1, tPrivate.ScalarKs2, tPrivate.ScalarLs1, tPrivate.ScalarLs2, tPrivate.ScalarRs1, tPrivate.ScalarRs2)
		if err != nil {
			continue
		}
		tPublic := new(SignRequestPublicInt)
		tPublic.PointRs1 = tPrivate.PointRs1
		tPublic.PointRs2 = tPrivate.PointRs2
		tPublic.ScalarLs1 = tPrivate.ScalarLs1
		tPublic.ScalarLs2 = tPrivate.ScalarLs2

		return tPublic, tPrivate, nil
	}
}

// Sign signs a blinded message
func (signer *Signer) Sign(blindmessage *BlindMessageInt, privateParams *SignRequestPrivateInt) (signature *BlindSignatureInt, err error) {
	if privateParams.IsUsed {
		return nil, eccutil.ErrParamReuse
	}
	//cparams := signer.curve.curve.Params()
	privkeyInt := new(big.Int)
	privkeyInt = privkeyInt.SetBytes(signer.privkey)

	_, err = signer.curve.TestParams(privkeyInt, blindmessage.M1, blindmessage.M2, privateParams.ScalarRs1, privateParams.ScalarKs1, privateParams.ScalarLs1, privateParams.ScalarRs2, privateParams.ScalarKs2, privateParams.ScalarLs2)
	if err != nil {
		return nil, err // Should never fire
	}

	mt1 := eccutil.ManyMult(privkeyInt, blindmessage.M1)                                               // SigPriv * m1
	mt2 := eccutil.ManyMult(privkeyInt, blindmessage.M2)                                               // SigPriv * m2
	ms1 := eccutil.ManyMult(privateParams.ScalarRs1, privateParams.ScalarKs1, privateParams.ScalarLs1) // rs1 * k1 * l1
	ms2 := eccutil.ManyMult(privateParams.ScalarRs2, privateParams.ScalarKs2, privateParams.ScalarLs2) // rs2 * k2 * l2

	ss1, ss2 := new(big.Int), new(big.Int)
	ss1 = ss1.Sub(mt1, ms1)                   // (SigPriv * m1) - (rs1 * k1 * l1)
	ss2 = ss2.Sub(mt2, ms2)                   // (SigPriv * m2) - (rs2 * k2 * l2)
	ss1 = ss1.Mod(ss1, signer.curve.Params.N) // ss1 = (SigPriv * m1 - rs1 * k1 * l1)  mod N
	ss2 = ss2.Mod(ss2, signer.curve.Params.N) // ss2 = (SigPriv * m2 - rs2 * k2 * l2)  mod N
	signaturet := new(BlindSignatureInt)
	signaturet.ScalarS1 = ss1
	signaturet.ScalarS2 = ss2
	return signaturet, nil
}

/*

type SignRequestPrivate struct {
	ScalarKs1, ScalarKs2 *big.Int // k parameters. Private.  kn x curve.G == Rn
	PointRs1, PointRs2   *Point   // R points. Public data, but kept for reverence
	ScalarLs1, ScalarLs2 *big.Int // l parameters. Public data, but kept for reverence
	ScalarRs1, ScalarRs2 *big.Int // x coordinates of PointRs1, PointRs2. Public. Pre-calculated.
	IsUsed               bool
}


Signer:
	curve.Sign
		Input:
			from Self: SigPriv, ks1, ks2, l1, l2
			from Requestor: m1, m2
		Calculation:
			Rs1 = ks1 x GeneratorPoint
			Rs2 = ks2 x GeneratorPoint
			rs1 = Rs1.x mod P
			rs2 = Rs2.x mod P

			ss1 = SigPriv * m1 - rs1 * k1 * l1  mod N
			ss2 = SigPriv * m2 - rs2 * k2 * l2  mod N
		Public: ss1, ss2
		Destroy against future use: ks1, ks2 , l1, l2)
*/
