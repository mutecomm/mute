// Package keylookup implements key lookup calls
package keylookup

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mutecomm/mute/serviceguard/common/constants"
	"github.com/mutecomm/mute/serviceguard/common/jsonclient"
	"github.com/mutecomm/mute/serviceguard/common/keypool"
	"github.com/mutecomm/mute/serviceguard/common/signkeys"

	"github.com/agl/ed25519"
)

var (
	// ErrBadSigner is returned if a verification pubkey list was signed by the wrong signer
	ErrBadSigner = errors.New("keylookup: Bad Signer")
	// ErrParams is returned if a call returned bad parameters
	ErrParams = errors.New("keylookup: Bad RPC parameters")
	// ErrBadSignature signals that a packet signature did not verify
	ErrBadSignature = errors.New("keylookup: Bad signature")
)

// DefaultClientFactory is the default factory for new clients
var DefaultClientFactory = jsonclient.New

// ServiceURL is the default URL for the keylookup service
var ServiceURL = constants.KeyLookupURL

// LookupClient implements a key lookup client
type LookupClient struct {
	KeyPool        *keypool.KeyPool
	ClientFactory  func(string, []byte) (*jsonclient.URLClient, error)
	ServiceGuardCA []byte // The CA of the serviceguard, if any
	PubKey         *[ed25519.PublicKeySize]byte
}

// New returns a new key lookup client
func New(keyPool *keypool.KeyPool, cacert []byte, pubKey *[ed25519.PublicKeySize]byte) *LookupClient {
	lc := new(LookupClient)
	lc.KeyPool = keyPool
	lc.ServiceGuardCA = cacert
	lc.ClientFactory = DefaultClientFactory
	lc.PubKey = pubKey
	return lc
}

// GetKey tries to lookup a key from the lookup service
func (klc LookupClient) GetKey(keyid *[signkeys.KeyIDSize]byte) (*signkeys.PublicKey, error) {
	keyMarshalled, err := klc.getKey(keyid[:])
	if err != nil {
		return nil, err
	}
	loadKey, err := new(signkeys.PublicKey).Unmarshal(keyMarshalled)
	if err != nil {
		return nil, err
	}
	return loadKey, nil
}

// getKey fetches a key from lookup
func (klc LookupClient) getKey(keyid []byte) ([]byte, error) {
	method := "PublicService.LookupKey"
	client, err := klc.ClientFactory(ServiceURL, klc.ServiceGuardCA)
	if err != nil {
		return nil, err
	}
	data, err := client.JSONRPCRequest(method, struct{ KeyID string }{KeyID: hex.EncodeToString(keyid)})
	if err != nil {
		return nil, err
	}
	if _, ok := data["Key"]; ok {
		keyMarshalled, err := base64.StdEncoding.DecodeString(data["Key"].(string))
		if err != nil {
			return nil, err
		}
		return keyMarshalled, nil
	}
	return nil, ErrParams
}

// RegisterStorage adds the lookup client to the keypool storage to accomplish automatic fetches. This should be
// used with great care since it locks the keypool during fetch (which can be many minutes).
func (klc *LookupClient) RegisterStorage() {
	fetchfunc := func(keyid []byte) (marshalledKey []byte, err error) {
		marshalledKey, err = klc.getKey(keyid)
		if err != nil {
			return
		}
		loadKey, err := new(signkeys.PublicKey).Unmarshal(marshalledKey)
		if err != nil {
			return nil, err
		}
		keyidX, err := klc.KeyPool.LoadKeyUnsafe(loadKey)
		if err != nil && err != keypool.ErrExists {
			return nil, err
		}
		klc.KeyPool.SaveKeyUnsafe(*keyidX)
		return
	}
	klc.KeyPool.RegisterStorage(fetchfunc, nil, nil)
}

// GetVerifyList requests a list of known issuer keys from the lookup service
func (klc LookupClient) GetVerifyList() ([][ed25519.PublicKeySize]byte, error) {
	var sig [ed25519.SignatureSize]byte
	var pk [ed25519.PublicKeySize]byte
	method := "PublicService.VerifyKeys"
	client, err := klc.ClientFactory(ServiceURL, klc.ServiceGuardCA)
	if err != nil {
		return nil, err
	}
	data, err := client.JSONRPCRequest(method, nil)
	if err != nil {
		return nil, err
	}
	if _, ok := data["PublicKey"]; !ok {
		return nil, ErrParams
	}
	if _, ok := data["Signature"]; !ok {
		return nil, ErrParams
	}
	if _, ok := data["KeyList"]; !ok {
		return nil, ErrParams
	}
	pubKey, err := hex.DecodeString(data["PublicKey"].(string))
	if err != nil {
		return nil, ErrParams
	}
	copy(pk[:], pubKey)
	if pk != *klc.PubKey {
		return nil, ErrBadSigner
	}

	signature, err := hex.DecodeString(data["Signature"].(string))
	if err != nil {
		return nil, ErrParams
	}
	copy(sig[:], signature)
	keylist := data["KeyList"].(string)
	ok := ed25519.Verify(klc.PubKey, []byte(keylist), &sig)
	if !ok {
		return nil, ErrBadSignature
	}
	keylistSlice := strings.Split(keylist, ", ")
	keylistRet := make([][ed25519.PublicKeySize]byte, 0, len(keylistSlice))
	for _, keyS := range keylistSlice {
		var keyA [ed25519.PublicKeySize]byte
		dk, err := hex.DecodeString(keyS)
		if err != nil {
			return nil, err
		}
		copy(keyA[:], dk)
		keylistRet = append(keylistRet, keyA)
	}
	return keylistRet, nil
}
