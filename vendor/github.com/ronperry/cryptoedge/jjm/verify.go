package jjm

/*
Verification phase:
	Public:
		curve.Verify
			Input:
				from Signer: SigPub
				from Requestor: m, s, r, R
			Calculation:
				m x SugPub =? s x Generator + r x R
			Output: true/false
*/

// Verify verifies that a signature does actually verify for a given message and signer public key
func (client BlindingClient) Verify(msg []byte, signature *SignatureInt) bool {
	// m x SugPub =? s x Generator + r x R
	lsP := client.curve.ScalarMult(client.PubKey, msg)                           // m x SugPub
	rsP1 := client.curve.ScalarBaseMult(signature.ScalarS.Bytes())               // s x Generator
	rsP2 := client.curve.ScalarMult(signature.PointR, signature.ScalarR.Bytes()) // r x R
	rsP := client.curve.AddPoints(rsP1, rsP2)                                    // (s x Generator) + (r x R)
	if lsP.X.Cmp(rsP.X) == 0 && lsP.Y.Cmp(rsP.Y) == 0 {
		return true
	}
	return false
}
