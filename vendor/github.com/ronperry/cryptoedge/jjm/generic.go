// Package jjm implements the JJM blind signature scheme over ECC
package jjm

// Implementation of generic blinding interface over JJM

import (
	"fmt"
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/genericblinding"
)

// GenericBlindingServer implements JJM blinding over generic interface
type GenericBlindingServer struct {
	Signer
}

// GenericBlindingClient a blinding client
type GenericBlindingClient struct {
	BlindingClient
}

// NewGenericBlindingServer returns blinding server over generic interface (GenericBlindingServer)
func NewGenericBlindingServer(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve) *GenericBlindingServer {
	bs := new(GenericBlindingServer)
	bs.curve = curve
	bs.pubkey = pubkey
	bs.privkey = privkey
	return bs
}

// GetParams returns per-signature blinding parameters
func (server *GenericBlindingServer) GetParams() (genericblinding.BlindingParamClient, genericblinding.BlindingParamServer, error) {
	bs := NewSigner(server.privkey, server.pubkey, server.curve)
	pub, priv, err := bs.NewSignRequest()
	if err != nil {
		return nil, nil, err
	}
	clientparams := NewBlindingParamClient(server.pubkey)
	clientparams.PointRs1, clientparams.PointRs2 = *pub.PointRs1, *pub.PointRs2
	clientparams.ScalarLs1, clientparams.ScalarLs2 = pub.ScalarLs1, pub.ScalarLs2

	serverparams := NewBlindingParamServer(server.pubkey)
	serverparams.ScalarKs1, serverparams.ScalarKs2 = priv.ScalarKs1, priv.ScalarKs2
	serverparams.PointRs1, serverparams.PointRs2 = *priv.PointRs1, *priv.PointRs2
	serverparams.ScalarLs1, serverparams.ScalarLs2 = priv.ScalarLs1, priv.ScalarLs2
	serverparams.ScalarRs1, serverparams.ScalarRs2 = priv.ScalarRs1, priv.ScalarRs2
	serverparams.IsUsed = false

	return clientparams, serverparams, nil
}

// Sign a blind message
func (server *GenericBlindingServer) Sign(bpsi genericblinding.BlindingParamServer, bmi genericblinding.BlindMessage) (genericblinding.BlindSignature, error) {
	_, err := genericblinding.MatchMessage(bpsi, SchemeName, genericblinding.TypeBlindingParamServer, server.pubkey)
	if err != nil {
		return nil, err
	}
	bps, ok := bpsi.(BlindingParamServer)
	if !ok {
		return nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(bmi, SchemeName, genericblinding.TypeBlindMessage, server.pubkey)
	if err != nil {
		return nil, err
	}
	bm, ok := bmi.(BlindMessage)
	if !ok {
		fmt.Println("Message")
		return nil, genericblinding.ErrBadType
	}

	bs := NewSigner(server.privkey, server.pubkey, server.curve)
	blindmessage := new(BlindMessageInt)
	blindmessage.M1, blindmessage.M2 = bm.M1, bm.M2
	privateParams := new(SignRequestPrivateInt)
	privateParams.ScalarKs1, privateParams.ScalarKs2 = bps.ScalarKs1, bps.ScalarKs2
	privateParams.PointRs1, privateParams.PointRs2 = &bps.PointRs1, &bps.PointRs2
	privateParams.ScalarLs1, privateParams.ScalarLs2 = bps.ScalarLs1, bps.ScalarLs2
	privateParams.ScalarRs1, privateParams.ScalarRs2 = bps.ScalarRs1, bps.ScalarRs2

	signature, err := bs.Sign(blindmessage, privateParams)
	if err != nil {
		return nil, err
	}
	blindsig := NewBlindSignature(server.pubkey)
	blindsig.ScalarS1, blindsig.ScalarS2 = signature.ScalarS1, signature.ScalarS2
	return blindsig, nil
}

// NewGenericBlindingClient returns a client for generic blinding interface
func NewGenericBlindingClient(pubkey *eccutil.Point, curve *eccutil.Curve) *GenericBlindingClient {
	c := new(GenericBlindingClient)
	c.curve = curve
	c.PubKey = pubkey
	return c
}

// Blind a message
func (client *GenericBlindingClient) Blind(bpci genericblinding.BlindingParamClient, cmi genericblinding.ClearMessage) (genericblinding.BlindingFactors, genericblinding.BlindMessage, error) {
	_, err := genericblinding.MatchMessage(bpci, SchemeName, genericblinding.TypeBlindingParamClient, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	bpc, ok := bpci.(BlindingParamClient)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}
	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	bc := NewBlindingClient(client.curve, client.PubKey)
	serverParams := new(SignRequestPublicInt)
	serverParams.PointRs1, serverParams.PointRs2 = &bpc.PointRs1, &bpc.PointRs2
	serverParams.ScalarLs1, serverParams.ScalarLs2 = bpc.ScalarLs1, bpc.ScalarLs2

	privateParams, err := bc.CalculateBlindingParams(serverParams)
	if err != nil {
		return nil, nil, err
	}
	blindmessage, err := bc.Blind(cm.UniqueID(), serverParams, privateParams)
	if err != nil {
		return nil, nil, err
	}
	bf := NewBlindingFactors(client.PubKey)
	bf.ScalarW, bf.ScalarZ = privateParams.ScalarW, privateParams.ScalarZ
	bf.ScalarE, bf.ScalarD = privateParams.ScalarE, privateParams.ScalarD
	bf.ScalarA, bf.ScalarB = privateParams.ScalarA, privateParams.ScalarB
	bf.PointR1, bf.PointR2 = *privateParams.PointR1, *privateParams.PointR2
	bf.ScalarR1, bf.ScalarR2 = privateParams.ScalarR1, privateParams.ScalarR2
	bf.ScalarRs1, bf.ScalarRs2 = privateParams.ScalarRs1, privateParams.ScalarRs2
	bf.IsUsed = false

	bm := NewBlindMessage(client.PubKey)
	bm.M1, bm.M2 = blindmessage.M1, blindmessage.M2

	return bf, bm, nil
}

// Unblind a signature
func (client *GenericBlindingClient) Unblind(bfi genericblinding.BlindingFactors, cmi genericblinding.ClearMessage, bsi genericblinding.BlindSignature) (genericblinding.ClearSignature, genericblinding.ClearMessage, error) {
	_, err := genericblinding.MatchMessage(bfi, SchemeName, genericblinding.TypeBlindingFactors, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	bf, ok := bfi.(BlindingFactors)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(bsi, SchemeName, genericblinding.TypeBlindSignature, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	bs, ok := bsi.(BlindSignature)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}
	bc := NewBlindingClient(client.curve, client.PubKey)
	blindSignature := new(BlindSignatureInt)
	blindSignature.ScalarS1, blindSignature.ScalarS2 = bs.ScalarS1, bs.ScalarS2

	blindingParams := new(BlindingParamsPrivateInt)
	blindingParams.ScalarW, blindingParams.ScalarZ = bf.ScalarW, bf.ScalarZ
	blindingParams.ScalarE, blindingParams.ScalarD = bf.ScalarE, bf.ScalarD
	blindingParams.ScalarA, blindingParams.ScalarB = bf.ScalarA, bf.ScalarB

	blindingParams.PointR1, blindingParams.PointR2 = &bf.PointR1, &bf.PointR2
	blindingParams.ScalarR1, blindingParams.ScalarR2 = bf.ScalarR1, bf.ScalarR2
	blindingParams.ScalarRs1, blindingParams.ScalarRs2 = bf.ScalarRs1, bf.ScalarRs2

	signature, err := bc.Unblind(blindSignature, blindingParams)
	if err != nil {
		return nil, nil, err
	}
	sig := NewClearSignature(client.PubKey)
	sig.PointR = *signature.PointR
	sig.ScalarS = signature.ScalarS
	sig.ScalarR = signature.ScalarR

	return sig, cm, nil
}

// Verify a signature
func (client *GenericBlindingClient) Verify(csi genericblinding.ClearSignature, cmi genericblinding.ClearMessage) (bool, error) {
	_, err := genericblinding.MatchMessage(csi, SchemeName, genericblinding.TypeClearSignature, client.PubKey)
	if err != nil {
		return false, err
	}
	cs, ok := csi.(ClearSignature)
	if !ok {
		return false, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return false, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return false, genericblinding.ErrBadType
	}

	bc := NewBlindingClient(client.curve, client.PubKey)
	signature := new(SignatureInt)
	signature.PointR = &cs.PointR
	signature.ScalarR = cs.ScalarR
	signature.ScalarS = cs.ScalarS
	return bc.Verify(cm.UniqueID(), signature), nil
}
