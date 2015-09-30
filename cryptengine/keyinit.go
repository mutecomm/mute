// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"math"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util/times"
)

func (ce *CryptEngine) addKeyInit(pseudonym, mixaddress, nymaddress, token string) error {
	// map pseudonym
	id, domain, err := identity.MapPlus(pseudonym)
	if err != nil {
		return err
	}
	// TODO: check token?
	// generate KeyInit
	msg, _, err := ce.keyDB.GetPrivateUID(id, true)
	if err != nil {
		return err
	}
	// TODO: fix parameter!
	ki, pubKeyHash, privateKey, err := msg.KeyInit(0,
		uint64(times.NinetyDaysLater()), 0, true, domain, mixaddress,
		nymaddress, cipher.RandReader)
	if err != nil {
		return err
	}
	var (
		kis          []*uid.KeyInit
		pubKeyHashes []string
		privateKeys  []string
		tokens       []string
	)
	kis = append(kis, ki)
	pubKeyHashes = append(pubKeyHashes, pubKeyHash)
	privateKeys = append(privateKeys, privateKey)
	tokens = append(tokens, token)
	// get JSON-RPC client and capabilities
	client, caps, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost,
		ce.homedir, "KeyInitRepository.AddKeyInit")
	if err != nil {
		return err
	}
	// call server
	content := make(map[string]interface{})
	content["SigPubKey"] = msg.UIDContent.SIGKEY.PUBKEY
	content["KeyInits"] = kis
	content["Tokens"] = tokens
	reply, err := client.JSONRPCRequest("KeyInitRepository.AddKeyInit", content)
	if err != nil {
		return err
	}
	// verify server signatures
	sigs, ok := reply["Signatures"].([]interface{})
	if !ok {
		return log.Errorf("cryptengine: could not add key inits for '%s'", msg.UIDContent.IDENTITY)
	}
	if len(kis) != len(sigs) {
		return log.Error("cryptengine: number of returned signatures does not equal number of sent key init messages")
	}
	for i, ki := range kis {
		sig, ok := sigs[i].(string)
		if !ok {
			return log.Error("cryptengine: signature is not a string")
		}
		// TODO: keyserver can return more than one SIGPUBKEY
		if err := ki.VerifySrvSig(sig, caps.SIGPUBKEYS[0]); err != nil {
			return err
		}
	}
	// store server key init messages and server signatures
	for i, ki := range kis {
		sig := sigs[i].(string) // cast has been checked already above
		if err := ce.keyDB.AddPrivateKeyInit(ki, pubKeyHashes[i], msg.SigPubKey(), privateKeys[i], sig); err != nil {
			return err
		}
	}
	return nil
}

func (ce *CryptEngine) fetchKeyInit(pseudonym string) error {
	// map pseudonym
	id, domain, err := identity.MapPlus(pseudonym)
	if err != nil {
		return err
	}
	// get corresponding public ID
	msg, _, found, err := ce.keyDB.GetPublicUID(id, math.MaxInt64) // TODO: use simpler API
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("not UID for '%s' found", id)
	}
	// get SIGKEYHASH
	sigKeyHash, err := msg.SigKeyHash()
	if err != nil {
		return err
	}
	// get JSON-RPC client and capabilities
	client, _, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost,
		ce.homedir, "KeyInitRepository.FetchKeyInit")
	if err != nil {
		return err
	}
	// call server
	content := make(map[string]interface{})
	content["SigKeyHash"] = sigKeyHash
	reply, err := client.JSONRPCRequest("KeyInitRepository.FetchKeyInit", content)
	if err != nil {
		return err
	}
	rep, ok := reply["KeyInit"].(string)
	if !ok {
		return log.Errorf("cryptengine: could not fetch key init for '%s'", sigKeyHash)
	}
	ki, err := uid.NewJSONKeyInit([]byte(rep))
	if err != nil {
		return err
	}
	// store public key init message
	if err := ce.keyDB.AddPublicKeyInit(ki); err != nil {
		return err
	}
	return nil
}

func (ce *CryptEngine) flushKeyInit(pseudonym string) error {
	// map pseudonym
	id, domain, err := identity.MapPlus(pseudonym)
	if err != nil {
		return err
	}
	// get corresponding public ID
	msg, _, err := ce.keyDB.GetPrivateUID(id, true)
	if err != nil {
		return err
	}
	// get JSON-RPC client and capabilities
	client, _, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost,
		ce.homedir, "KeyInitRepository.FlushKeyInit")
	if err != nil {
		return err
	}
	// call server
	content := make(map[string]interface{})
	nonce, signature := msg.SignNonce()
	content["SigPubKey"] = msg.UIDContent.SIGKEY.PUBKEY
	content["Nonce"] = nonce
	content["Signature"] = signature
	_, err = client.JSONRPCRequest("KeyInitRepository.FlushKeyInit", content)
	if err != nil {
		return err
	}
	/*
		rep, ok := reply["KeyInit"].(string)
		if !ok {
			return log.Errorf("cryptengine: could not fetch key init for '%s'", sigKeyHash)
		}
		_, err = uid.NewJSONKeyInit([]byte(rep))
		if err != nil {
			return err
		}
	*/
	return nil
}
