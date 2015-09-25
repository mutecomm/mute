package jjm

/*
Blinding phase:
	Requestor:
		MUST test input (r1,r2,ls1,ls2)
		curve.Blind:
			Input:
				from Signer: Rs1, Rs2, ls1, ls2
				from Self: Message m
			Calculation:
				Random: w, z
					Int.GCD(w, z, e, d) == 1  // Double check ordering. ew + dz == 1
				Random: a, b
				R1 = w * a * ls1 x Rs1
				R2 = z * b * ls2 x Rs2
				r1 = R1.x mod P , r1 != 0
				r2 = R2.x mod P , r1 != 0

				rs1 = Rs1.x mod P
				rs2 = Rs2.x mod P

				// rs1, rs2, r1, r2 must be GCD(x, P)/relative prime to P. P should be a prime, so that's not a problem
				r1i = Int.ModInv(r1, P)
				r2i = Int.ModInv(r2, P)
				ai = Int.ModInv(a, P)
				bi = Int.ModInv(b, P)
				m1 = e * m * rs1 * r1i * r2i * ai  mod N
				m2 = e * m * rs2 * r1i * r2i * bi  mod N
			Public: m1, m2
			Secret: a,b,w,z,e,d,m
Unblinding phase:
	Requestor:
		curve.Unblind:
			Input:
				from Self: rs1, rs2, r1, r2, R1, R2, w, z, a, b
				from Signer: ss1, ss2
			Calculation:
				rs1i = Int.ModInv(rs1, P)
				rs2i = Int.ModInv(rs2, P)
				s1 = ss1 * rs1i * r1 * r2 * w * a  mod N
				s2 = ss2 * rs2i * r1 * r2 * z * b  mod N
				s = s1 + s2
				R = R1 + R2
				r = (r1 * r2) mod N
			Output:
				s, r , R
*/

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// BlindMessageInt contains a blinded message to be signed
type BlindMessageInt struct {
	M1, M2 *big.Int
	params *SignRequestPublicInt
}

// BlindingParamsPrivateInt holds the blinding parameters private to the requestor. To be used exactly once.
type BlindingParamsPrivateInt struct {
	ScalarW, ScalarZ *big.Int // w,z random. GCD(w,z) == 1
	ScalarE, ScalarD *big.Int // e,d -> ew + dz == 1
	ScalarA, ScalarB *big.Int // random

	PointR1, PointR2     *eccutil.Point // R1=w * a * l1 x RS1, R2=w*a*l2 x RS2
	ScalarR1, ScalarR2   *big.Int       // R1.x, R2.x  mod P !=0 . Precalculated
	ScalarRs1, ScalarRs2 *big.Int       // Simplification
	IsUsed               bool
}

// SignatureInt is the unblinded signature
type SignatureInt struct {
	PointR  *eccutil.Point
	ScalarS *big.Int
	ScalarR *big.Int
}

// BlindingClient a blinding client
type BlindingClient struct {
	curve  *eccutil.Curve
	PubKey *eccutil.Point
}

// NewBlindingClient returns a new BlindingClient
func NewBlindingClient(curve *eccutil.Curve, pubKey *eccutil.Point) *BlindingClient {
	bc := new(BlindingClient)
	bc.curve = curve
	bc.PubKey = pubKey
	return bc
}

// Unblind a signature
func (client BlindingClient) Unblind(blindSignature *BlindSignatureInt, BlindingParams *BlindingParamsPrivateInt) (signature *SignatureInt, err error) {
	// ToDo: Test Params
	ScalarRs1Inv, err := client.curve.ModInverse(BlindingParams.ScalarRs1) // inv(rs1)
	if err != nil {
		return nil, err // should never happen
	}
	ScalarRs2Inv, err := client.curve.ModInverse(BlindingParams.ScalarRs2) // inv(rs2)
	if err != nil {
		return nil, err // should never happen
	}
	ScalarR1R2 := eccutil.ManyMult(BlindingParams.ScalarR1, BlindingParams.ScalarR2) // r1 * r2

	ScalarS1 := eccutil.ManyMult(blindSignature.ScalarS1, ScalarRs1Inv, ScalarR1R2, BlindingParams.ScalarW, BlindingParams.ScalarA) // ss1 * (inv(rs1)) * (r1 * r2) * w * a
	ScalarS2 := eccutil.ManyMult(blindSignature.ScalarS2, ScalarRs2Inv, ScalarR1R2, BlindingParams.ScalarZ, BlindingParams.ScalarB) // ss2 * (inv(rs2)) * (r1 * r2) * z * b
	//cparams := curve.curve.Params()
	ScalarS1 = ScalarS1.Mod(ScalarS1, client.curve.Params.N) // s1 = (ss1 * inv(rs1) * r1 * r2 * w * a)  mod N
	ScalarS2 = ScalarS2.Mod(ScalarS2, client.curve.Params.N) // s2 = (ss2 * inv(rs2) * r1 * r2 * z * b)  mod N
	ScalarS := new(big.Int)
	ScalarS = ScalarS.Add(ScalarS1, ScalarS2) // s = s1 + s2

	PointR := client.curve.AddPoints(BlindingParams.PointR1, BlindingParams.PointR2) // R = R1 + R2

	ScalarR := eccutil.ManyMult(BlindingParams.ScalarR1, BlindingParams.ScalarR2) // r1 * r2
	ScalarR = ScalarR.Mod(ScalarR, client.curve.Params.N)                         //r = (r1 * r2) mod N

	signaturet := new(SignatureInt)
	signaturet.PointR = PointR
	signaturet.ScalarS = ScalarS
	signaturet.ScalarR = ScalarR
	return signaturet, nil
}

// Blind blinds a message msg for blinding using params. Returns blinded message or error
func (client BlindingClient) Blind(msg []byte, SignerParams *SignRequestPublicInt, BlindingParams *BlindingParamsPrivateInt) (blindmessage *BlindMessageInt, err error) {
	// Test message as int
	msgi := new(big.Int)
	msgi = msgi.SetBytes(msg)
	_, err = client.curve.TestParams(msgi)
	if err != nil {
		return nil, err
	}
	// Test BlindingParams as unused
	if BlindingParams.IsUsed {
		return nil, eccutil.ErrParamReuse
	}
	ScalarRs1, err := client.curve.ExtractR(SignerParams.PointRs1)
	if err != nil {
		return nil, err
	}
	ScalarRs2, err := client.curve.ExtractR(SignerParams.PointRs2)
	if err != nil {
		return nil, err
	}
	_, err = client.curve.TestParams(ScalarRs1, ScalarRs2, SignerParams.ScalarLs1, SignerParams.ScalarLs2)
	if err != nil {
		return nil, err
	}
	//inverse: ScalarA, ScalarB, ScalarR1, ScalarR2
	ScalarAInverse, err := client.curve.ModInverse(BlindingParams.ScalarA)
	if err != nil {
		return nil, err // Should not ever happen
	}
	ScalarBInverse, err := client.curve.ModInverse(BlindingParams.ScalarB)
	if err != nil {
		return nil, err // Should not ever happen
	}
	ScalarR1Inverse, err := client.curve.ModInverse(BlindingParams.ScalarR1)
	if err != nil {
		return nil, err // Should not ever happen
	}
	ScalarR2Inverse, err := client.curve.ModInverse(BlindingParams.ScalarR2)
	if err != nil {
		return nil, err // Should not ever happen
	}

	t1 := eccutil.ManyMult(BlindingParams.ScalarE, msgi, ScalarRs1, ScalarR1Inverse, ScalarR2Inverse, ScalarAInverse) // t1 = e * m * rs1 * r1i * r2i * ai
	// This differs from the paper which says ScalarE here. That is an error in the paper, as shown in the proof that uses ScalarD
	t2 := eccutil.ManyMult(BlindingParams.ScalarD, msgi, ScalarRs2, ScalarR1Inverse, ScalarR2Inverse, ScalarBInverse) // t2 = e * m * rs2 * r1i * r2i * bi  (should that not be d instead of e? or reverse?)

	//cparams := curve.curve.Params()
	m1, m2 := new(big.Int), new(big.Int)
	m1 = m1.Mod(t1, client.curve.Params.N)
	m2 = m2.Mod(t2, client.curve.Params.N)

	_, err = client.curve.TestParams(m1, m2) // Should never fire
	if err != nil {
		return nil, err
	}

	blindmessaget := new(BlindMessageInt)
	blindmessaget.M1 = m1
	blindmessaget.M2 = m2
	blindmessaget.params = SignerParams

	return blindmessaget, nil
}

// CalculateBlindingParams generates the w,z,e,d,a,b privateParams blinding parameters and calculates r1,r2 (included in privateParams)
func (client BlindingClient) CalculateBlindingParams(params *SignRequestPublicInt) (privateParams *BlindingParamsPrivateInt, err error) {
	var loopcount int
	for {
		if loopcount > eccutil.MaxLoopCount {
			return nil, eccutil.ErrMaxLoop
		}
		ScalarRs1, err := client.curve.ExtractR(params.PointRs1)
		if err != nil {
			return nil, err
		}
		ScalarRs2, err := client.curve.ExtractR(params.PointRs2)
		if err != nil {
			return nil, err
		}

		loopcount++
		ScalarW, err := client.curve.GenNVint() // This limits W substantially and is likely unnecessary
		if err != nil {
			continue
		}
		ScalarZ, err := client.curve.GenNVint() // This limits Z substantially and is likely unnecessary
		if err != nil {
			continue
		}
		ScalarE := new(big.Int)
		ScalarD := new(big.Int)

		gcd := new(big.Int)
		gcd = gcd.GCD(ScalarE, ScalarD, ScalarW, ScalarZ) // Int.GCD(w, z, e, d) == 1
		if gcd.Cmp(eccutil.TestOne) != 0 {
			continue
		}

		ScalarA, err := client.curve.GenNVint() // This limits A substantially and is likely unnecessary
		if err != nil {
			continue
		}
		ScalarB, err := client.curve.GenNVint() // This limits B substantially and is likely unnecessary
		if err != nil {
			continue
		}
		_, _ = ScalarA, ScalarB
		ta := eccutil.ManyMult(ScalarW, ScalarA, params.ScalarLs1).Bytes() // w * a * ls1 -> byte ta
		tb := eccutil.ManyMult(ScalarZ, ScalarB, params.ScalarLs2).Bytes() // z * b * ls2 -> byte tb

		PointR1 := client.curve.ScalarMult(params.PointRs1, ta)
		PointR2 := client.curve.ScalarMult(params.PointRs2, tb)

		ScalarR1, err := client.curve.ExtractR(PointR1) // scalarmult(ta,R1).x mod P  != 0
		if err != nil {
			continue
		}
		ScalarR2, err := client.curve.ExtractR(PointR2) // scalarmult(tb,R2).x mod P  != 0
		if err != nil {
			continue
		}

		// Probably useless test
		_, err = client.curve.TestParams(ScalarW, ScalarZ, ScalarE, ScalarD, ScalarA, ScalarB, ScalarR1, ScalarR2, ScalarRs1, ScalarRs2, params.ScalarLs1, params.ScalarLs2)
		if err != nil {
			continue
		}
		bp := new(BlindingParamsPrivateInt)
		bp.ScalarW, bp.ScalarZ = ScalarW, ScalarZ
		bp.ScalarE, bp.ScalarD = ScalarE, ScalarD
		bp.ScalarA, bp.ScalarB = ScalarA, ScalarB
		bp.PointR1, bp.PointR2 = PointR1, PointR2
		bp.ScalarR1, bp.ScalarR2 = ScalarR1, ScalarR2
		bp.ScalarRs1, bp.ScalarRs2 = ScalarRs1, ScalarRs2
		bp.IsUsed = false
		return bp, nil
	}
}
