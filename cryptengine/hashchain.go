// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/cipher/aes256"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
)

// syncHashChain brings local hash chain in sync with key server at the given
// domain. It just downloads the new entries and does not validate them
// whatsoever.
func (ce *CryptEngine) syncHashChain(domain string) error {
	// get JSON-RPC client
	client, _, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost, ce.homedir,
		"KeyHashchain.FetchLastHashChain")
	if err != nil {
		return err
	}
	// get last hash chain entry from key server
	reply, err := client.JSONRPCRequest("KeyHashchain.FetchLastHashChain", nil)
	if err != nil {
		return err
	}
	// parse hash chain entry
	hcEntry, ok := reply["HCEntry"].(string)
	if !ok {
		return log.Error("cryptengine: fetch last hash chain entry reply has the wrong type")
	}
	// parse hash chain position
	hcPosFloat := reply["HCPos"].(float64)
	if !ok {
		return log.Error("cryptengine: fetch last hash chain position reply has the wrong type")
	}
	hcPos := uint64(hcPosFloat)
	log.Debugf("cryptengine: last HC#%d: %s", hcPos, hcEntry)

	// determine what we already have
	pos, found, err := ce.keyDB.GetLastHashChainPos(domain)
	if err != nil {
		return err
	}
	var start, end uint64
	if found {
		log.Debugf("cryptengine: last position for domain '%s': %d", domain, pos)
		if pos >= hcPos {
			// already in sync
			log.Debugf("cryptengine: hash chain already in sync")
			return nil
		}
		// sync the missing entries
		start = pos + 1
		end = hcPos
	} else {
		// no entries found -> get everything
		start = 0
		end = hcPos
		log.Debugf("cryptengine: no entry found for domain '%s'", domain)
	}
	// get JSON-RPC client
	client, _, err = ce.cache.Get(domain, ce.keydPort, ce.keydHost, ce.homedir,
		"KeyHashchain.FetchHashChain")
	if err != nil {
		return err
	}
	// get missing chain entries
	content := make(map[string]interface{})
	content["StartPosition"] = start
	content["EndPosition"] = end
	reply, err = client.JSONRPCRequest("KeyHashchain.FetchHashChain", content)
	if err != nil {
		return err
	}
	// parse hash chain entries
	hcEntries, ok := reply["HCEntries"].([]interface{})
	if !ok {
		return log.Error("cryptengine: fetch hash chain entries reply has the wrong type")
	}
	// parse first hash chain position
	hcPosFirstFloat := reply["HCFirstPos"].(float64)
	if !ok {
		return log.Error("cryptengine: fetch hash chain first position reply has the wrong type")
	}
	hcFirstPos := uint64(hcPosFirstFloat)
	for i := hcFirstPos; i <= hcPos; i++ {
		entry, ok := hcEntries[i-hcFirstPos].(string)
		if !ok {
			return log.Error("cryptengine: fetch hash chain entry is not a string")
		}
		log.Debugf("cryptengine: HC#%d: %s", i, entry)
		// store entry in database
		err := ce.keyDB.AddHashChainEntry(domain, i, entry)
		if err != nil {
			return nil
		}
	}

	return nil
}

// validateHashChain validates the local hash chain for the given domain.
// That is, it checks that each entry has the correct length and the links are
// valid.
func (ce *CryptEngine) validateHashChain(domain string) error {
	// make sure we have a hashchain for the given domain
	max, found, err := ce.keyDB.GetLastHashChainPos(domain)
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("no hash chain entries found for domain '%s'", domain)
	}

	var hashEntryN, TYPE, NONCE, HashID, CrUID, UIDIndex, hashEntryNminus1 []byte
	for i := uint64(0); i <= max; i++ {
		entry, err := ce.keyDB.GetHashChainEntry(domain, i)
		if err != nil {
			return err
		}
		log.Debugf("cryptengine: validate entry %d: %s", i, entry)

		if i == 0 {
			hashEntryNminus1 = make([]byte, sha256.Size)
		} else {
			hashEntryNminus1 = hashEntryN
		}
		hashEntryN, TYPE, NONCE, HashID, CrUID, UIDIndex, err = hashchain.SplitEntry(entry)
		if err != nil {
			return err
		}
		if !bytes.Equal(TYPE, hashchain.Type) {
			return log.Error("cryptengine: invalid hash chain entry type")
		}

		entryN := make([]byte, 153)
		copy(entryN, TYPE)
		copy(entryN[1:], NONCE)
		copy(entryN[9:], HashID)
		copy(entryN[41:], CrUID)
		copy(entryN[89:], UIDIndex)
		copy(entryN[121:], hashEntryNminus1)
		if !bytes.Equal(hashEntryN, cipher.SHA256(entryN)) {
			return log.Errorf("cryptengine: hash chain entry %d invalid", i)
		}
	}

	// get all private identities for the given domain
	ids, err := ce.keyDB.GetPrivateIdentitiesForDomain(domain)
	if err != nil {
		return err
	}

	// make sure UIDMessageReplies are recorded in hash chain
	for _, id := range ids {
		_, msgReply, err := ce.keyDB.GetPrivateUID(id, false)
		if err != nil {
			return err
		}
		if msgReply != nil && msgReply.ENTRY.HASHCHAINPOS <= max {
			entry, err := ce.keyDB.GetHashChainEntry(domain, msgReply.ENTRY.HASHCHAINPOS)
			if err != nil {
				return err
			}
			if entry != msgReply.ENTRY.HASHCHAINENTRY {
				return log.Errorf("cryptengine: hash chain entry differs from UIDMessageReply (%s)", id)
			}
		}
	}

	return nil
}

func (ce *CryptEngine) fetchUID(
	domain string,
	UIDIndex []byte,
) (*uid.MessageReply, error) {
	// get JSON-RPC client
	client, _, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost, ce.homedir,
		"KeyRepository.FetchUID")
	if err != nil {
		return nil, err
	}
	// Call KeyRepository.FetchUID
	content := make(map[string]interface{})
	content["UIDIndex"] = base64.Encode(UIDIndex)
	reply, err := client.JSONRPCRequest("KeyRepository.FetchUID", content)
	if err != nil {
		return nil, err
	}

	// Parse entry
	var entry uid.Entry
	rep, ok := reply["UIDMessageReply"].(map[string]interface{})
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID reply has the wrong return type")
	}
	e, ok := rep["ENTRY"].(map[string]interface{})
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID ENTRY has the wrong type")
	}
	entry.UIDMESSAGEENCRYPTED, ok = e["UIDMESSAGEENCRYPTED"].(string)
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID UIDMESSAGEENCRYPTED has the wrong type")
	}
	log.Debugf("cryptengine: UIDMessageEncrypted=%s", entry.UIDMESSAGEENCRYPTED)
	entry.HASHCHAINENTRY, ok = e["HASHCHAINENTRY"].(string)
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID HASHCHAINENTRY has the wrong type")
	}
	hcPos, ok := e["HASHCHAINPOS"].(float64)
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID HASHCHAINPOS has the wrong type")
	}
	entry.HASHCHAINPOS = uint64(hcPos)

	// Parse server signature
	srvSig, ok := rep["SERVERSIGNATURE"].(string)
	if !ok {
		return nil, log.Error("cryptengine: KeyRepository.FetchUID SERVERSIGNATURE has the wrong type")
	}

	msgReply := &uid.MessageReply{
		ENTRY:           entry,
		SERVERSIGNATURE: srvSig,
	}
	return msgReply, err
}

func (ce *CryptEngine) verifyServerSig(
	uid *uid.Message,
	msgReply *uid.MessageReply,
	position uint64,
) error {
	// For the first keyserver message we do not need to verify the server signature
	if uid.Localpart() == "keyserver" && uid.UIDContent.MSGCOUNT == 0 {
		return nil
	}

	// Get keyserver UID
	srvUID, _, found, err := ce.keyDB.GetPublicUID("keyserver@"+uid.Domain(), position)
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("cryptengine: no keyserver signature key found for domain '%s'", uid.Domain())
	}

	// Verify server signature
	if err := msgReply.VerifySrvSig(uid, srvUID.UIDContent.SIGKEY.PUBKEY); err != nil {
		return log.Error(err)
	}
	return nil
}

// searchHashChain searches the local hash chain corresponding to the given id
// for the id. It talks to the corresponding key server to retrieve necessary
// UIDMessageReplys and stores found UIDMessages in the local keyDB.
func (ce *CryptEngine) searchHashChain(id string, searchOnly bool) error {
	// map identity
	mappedID, domain, err := identity.MapPlus(id)
	if err != nil {
		return err
	}
	// make sure we have a hashchain for the given domain
	max, found, err := ce.keyDB.GetLastHashChainPos(domain)
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("no hash chain entries found for domain '%s'", domain)
	}

	var TYPE, NONCE, HashID, CrUID, UIDIndex []byte
	var matchFound bool
	for i := uint64(0); i <= max; i++ {
		hcEntry, err := ce.keyDB.GetHashChainEntry(domain, i)
		if err != nil {
			return err
		}
		log.Debugf("cryptengine: search hash chain entry %d: %s", i, hcEntry)

		_, TYPE, NONCE, HashID, CrUID, UIDIndex, err = hashchain.SplitEntry(hcEntry)
		if err != nil {
			return err
		}
		if !bytes.Equal(TYPE, hashchain.Type) {
			return log.Error("cryptengine: invalid hash chain entry type")
		}

		// Compute k1, k2 = CKDF(NONCE)
		k1, k2 := cipher.CKDF(NONCE)

		// Compute: HashIDTest = HASH(k1 | Identity)
		tmp := make([]byte, len(k1)+len(mappedID))
		copy(tmp, k1)
		copy(tmp[len(k1):], mappedID)
		HashIDTest := cipher.SHA256(tmp)

		// If NOT: HashID == HashIDTest: Continue
		if !bytes.Equal(HashID, HashIDTest) {
			continue
		}
		if searchOnly {
			return nil
		}
		log.Debugf("cryptengine: UIDIndex=%s", base64.Encode(UIDIndex))

		// Check UID already exists in keyDB
		_, pos, found, err := ce.keyDB.GetPublicUID(mappedID, i)
		if err != nil {
			return err
		}
		if found && pos == i {
			// UID exists already -> skip entry
			matchFound = true
			continue
		}

		// Compute: IDKEY = HASH(k2 | Identity)
		tmp = make([]byte, len(k2)+len(mappedID))
		copy(tmp, k2)
		copy(tmp[len(k2):], mappedID)
		IDKEY := cipher.SHA256(tmp)

		// Fetch from Key Repository: UIDMessageReply = GET(UIDIndex)
		msgReply, err := ce.fetchUID(domain, UIDIndex)
		if err != nil {
			return err
		}

		// Decrypt UIDHash = AES_256_CBC_Decrypt( IDKEY, CrUID)
		UIDHash := aes256.CBCDecrypt(IDKEY, CrUID)
		log.Debugf("cryptengine: UIDHash=%s", base64.Encode(UIDHash))

		// Decrypt UIDMessageReply.UIDMessage with UIDHash
		index, uid, err := msgReply.Decrypt(UIDHash)
		if err != nil {
			return err
		}
		log.Debugf("cryptengine: UIDMessage=%s", uid.JSON())

		// Check index
		if !bytes.Equal(index, UIDIndex) {
			return log.Errorf("cryptengine: index != UIDIndex")
		}

		// Verify self signature
		if err := uid.VerifySelfSig(); err != nil {
			return log.Error(err)
		}

		// Verify server signature
		if err := ce.verifyServerSig(uid, msgReply, i); err != nil {
			return err
		}

		// TODO: make sure the whole chain of UIDMessages is valid

		// Store UIDMessage
		if err := ce.keyDB.AddPublicUID(uid, i); err != nil {
			return err
		}
		matchFound = true

		// If no further entry can be found, the latest UIDMessage entry has been found
	}

	if matchFound {
		return nil
	}

	return log.Errorf("no hash chain entry found of id '%s'", id)
}

func (ce *CryptEngine) lookupHashChain(id string) error {
	// map identity
	mappedID, domain, err := identity.MapPlus(id)
	if err != nil {
		return err
	}
	// get JSON-RPC client
	client, _, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost, ce.homedir,
		"KeyHashchain.LookupUID")
	if err != nil {
		return err
	}
	// Call KeyHashchain.LookupUID
	content := make(map[string]interface{})
	content["Identity"] = mappedID
	reply, err := client.JSONRPCRequest("KeyHashchain.LookupUID", content)
	if err != nil {
		return err
	}
	hcPositions, ok := reply["HCPositions"].([]interface{})
	if !ok {
		if _, ok := reply["HCPositions"].(interface{}); !ok {
			return log.Errorf("lookup found no entry of id '%s'", id)
		}
		return log.Error("cryptengine: lookup ID reply has the wrong type")
	}
	var TYPE, NONCE, HashID, CrUID, UIDIndex []byte
	var matchFound bool
	for k, v := range hcPositions {
		hcPosFloat, ok := v.(float64)
		if !ok {
			return log.Errorf("cryptengine: lookup ID reply position entry %d has the wrong type", k)
		}
		hcPos := uint64(hcPosFloat)
		hcEntry, err := ce.keyDB.GetHashChainEntry(domain, hcPos)
		if err != nil {
			return err
		}
		_, TYPE, NONCE, HashID, CrUID, UIDIndex, err = hashchain.SplitEntry(hcEntry)
		if err != nil {
			return err
		}
		if !bytes.Equal(TYPE, hashchain.Type) {
			return log.Error("cryptengine: invalid entry type")
		}

		// Compute k1, k2 = CKDF(NONCE)
		k1, k2 := cipher.CKDF(NONCE)

		// Compute: HashIDTest = HASH(k1 | Identity)
		tmp := make([]byte, len(k1)+len(mappedID))
		copy(tmp, k1)
		copy(tmp[len(k1):], mappedID)
		HashIDTest := cipher.SHA256(tmp)

		// If NOT: HashID == HashIDTest: Continue
		if !bytes.Equal(HashID, HashIDTest) {
			return log.Error("cryptengine: lookup ID returned bogus position")
		}
		log.Debugf("cryptengine: UIDIndex=%s", base64.Encode(UIDIndex))

		// Check UID already exists in keyDB
		_, pos, found, err := ce.keyDB.GetPublicUID(mappedID, hcPos)
		if err != nil {
			return err
		}
		if found && pos == hcPos {
			// UID exists already -> skip entry
			matchFound = true
			continue
		}

		// Compute: IDKEY = HASH(k2 | Identity)
		tmp = make([]byte, len(k2)+len(mappedID))
		copy(tmp, k2)
		copy(tmp[len(k2):], mappedID)
		IDKEY := cipher.SHA256(tmp)

		// Fetch from Key Repository: UIDMessageReply = GET(UIDIndex)
		msgReply, err := ce.fetchUID(domain, UIDIndex)
		if err != nil {
			return err
		}

		// Decrypt UIDHash = AES_256_CBC_Decrypt( IDKEY, CrUID)
		UIDHash := aes256.CBCDecrypt(IDKEY, CrUID)
		log.Debugf("cryptengine: UIDHash=%s", base64.Encode(UIDHash))

		// Decrypt UIDMessageReply.UIDMessage with UIDHash
		index, uid, err := msgReply.Decrypt(UIDHash)
		if err != nil {
			return err
		}
		log.Debugf("cryptengine: UIDMessage=%s", uid.JSON())

		// Check index
		if !bytes.Equal(index, UIDIndex) {
			return log.Errorf("cryptengine: index != UIDIndex")
		}

		// Verify self signature
		if err := uid.VerifySelfSig(); err != nil {
			return log.Error(err)
		}

		// Verify server signature
		if err := ce.verifyServerSig(uid, msgReply, hcPos); err != nil {
			return err
		}

		// TODO: make sure the whole chain of UIDMessages is valid

		// Store UIDMessage
		if err := ce.keyDB.AddPublicUID(uid, hcPos); err != nil {
			return err
		}
		matchFound = true

		// If no further entry can be found, the latest UIDMessage entry has been found
	}

	if matchFound {
		return nil
	}

	return log.Errorf("lookup found no entry of id '%s'", id)
}

// showHashChain shows the hash chain of the given domain on output-fd.
func (ce *CryptEngine) showHashChain(domain string) error {
	// make sure we have a hashchain for the given domain
	max, found, err := ce.keyDB.GetLastHashChainPos(domain)
	if err != nil {
		return err
	}
	if !found {
		return log.Errorf("no hash chain entries found for domain '%s'", domain)
	}

	// show hash chain
	for i := uint64(0); i <= max; i++ {
		entry, err := ce.keyDB.GetHashChainEntry(domain, i)
		if err != nil {
			return err
		}
		fmt.Fprintln(ce.fileTable.OutputFP, entry)
	}

	return nil
}

// deleteHashChain deletes the local hash chain copy of the given domain.
func (ce *CryptEngine) deleteHashChain(domain string) error {
	return ce.keyDB.DelHashChain(domain)
}
