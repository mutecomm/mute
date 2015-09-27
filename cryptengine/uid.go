// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/uid/identity"
)

// generate a new nym and store it in keydb.
func (ce *CryptEngine) generate(
	pseudonym string,
	keyServer bool,
	outputfp *os.File,
) error {
	// map pseudonym
	id, domain, err := identity.MapPlus(pseudonym)
	if err != nil {
		return err
	}
	// create new UID
	// TODO: allow different PFS preferences
	lastEntry, err := ce.keyDB.GetLastHashChainEntry(domain)
	if err != nil {
		return err
	}
	uid, err := uid.Create(id, false, "", "", uid.Strict, lastEntry,
		cipher.RandReader)
	if err != nil {
		return err
	}
	if !keyServer {
		// store UID in keyDB
		if err := ce.keyDB.AddPrivateUID(uid); err != nil {
			return err
		}
	} else {
		// a private key for the keyserver is not stored in the keyDB
		var out bytes.Buffer
		if err := json.Indent(&out, []byte(uid.JSON()), "", "  "); err != nil {
			return err
		}
		fmt.Fprintln(outputfp, out.String())
		if keyServer {
			fmt.Fprintf(outputfp, "{\"PRIVSIGKEY\": \"%s\"}\n", uid.PrivateSigKey())
		}
	}
	log.Infof("nym '%s' generated successfully", id)
	return nil
}

func (ce *CryptEngine) registerOrUpdate(
	pseudonym, token, command, verb string,
) error {
	// map pseudonym
	id, domain, err := identity.MapPlus(pseudonym)
	if err != nil {
		return err
	}
	// TODO: check token?
	// get UID from keyDB
	msg, messageReply, err := ce.keyDB.GetPrivateUID(id, false)
	if err != nil {
		return err
	}
	if messageReply != nil {
		return log.Errorf("cryptengine: UID has already been %s", verb)
	}
	// get JSON-RPC client and capabilities
	client, caps, err := ce.cache.Get(domain, ce.keydPort, ce.keydHost,
		ce.homedir, "KeyRepository."+command)
	if err != nil {
		return err
	}
	log.Infof("cryptengine: returned sigpubkey: %s", caps.SIGPUBKEY)
	// register/update UID with key server
	content := make(map[string]interface{})
	content["UIDMessage"] = msg
	content["Token"] = token
	reply, err := client.JSONRPCRequest("KeyRepository."+command, content)
	if err != nil {
		return err
	}
	rep, ok := reply["UIDMessageReply"].(map[string]interface{})
	if !ok {
		return log.Errorf("cryptengine: %s reply has the wrong type", command)
	}

	// marshal the unstructured UIDMessageReply into a JSON byte array
	jsn, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// unmarshal the JSON byte array back into a UIDMessageReply
	msgReply, err := uid.NewJSONReply(string(jsn))
	if err != nil {
		return err
	}

	// store reply first to have proof, if the key server is cheating
	if err := ce.keyDB.AddPrivateUIDReply(msg, msgReply); err != nil {
		return err
	}

	// verify reply
	if err := msgReply.VerifySrvSig(msg, caps.SIGPUBKEY); err != nil {
		return err
	}

	log.Infof("nym '%s' %s successfully", id, verb)
	return nil
}

// register already generated nym (stored in keyDB) with key server.
func (ce *CryptEngine) register(pseudonym, tokenString string) error {
	return ce.registerOrUpdate(pseudonym, tokenString, "CreateUID", "registered")
}

// genupdate generates an update for the (registered) nym and stores it in keydb.
func (ce *CryptEngine) genupdate(pseudonym string) error {
	// map pseudonym
	id, err := identity.Map(pseudonym)
	if err != nil {
		return err
	}
	// get old UID from keyDB
	oldUID, _, err := ce.keyDB.GetPrivateUID(id, true)
	if err != nil {
		return err
	}
	// generate new UID
	newUID, err := oldUID.Update(cipher.RandReader)
	if err != nil {
		return err
	}
	// store new UID in keyDB
	if err := ce.keyDB.AddPrivateUID(newUID); err != nil {
		return err
	}
	return nil
}

// update an already generated nym update (stored in keyDB) with key server.
func (ce *CryptEngine) update(pseudonym, tokenString string) error {
	return ce.registerOrUpdate(pseudonym, tokenString, "UpdateUID", "updated")
}

// deleteUID deletes a nym.
func (ce *CryptEngine) deleteUID(pseudonym string, force bool) error {
	// map pseudonym
	id, err := identity.Map(pseudonym)
	if err != nil {
		return err
	}

	// get UID from keyDB
	msg, _, err := ce.keyDB.GetPrivateUID(id, false)
	if err != nil {
		return err
	}

	// ask for manual confirmation
	if !force {
		fmt.Fprintf(os.Stderr, "cryptengine: delete user ID %s and all it's key material? ",
			pseudonym)
		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return log.Error(err)
		}
		if !strings.HasPrefix(strings.ToLower(response), "y") {
			return log.Error("cryptengine: user ID deletion aborted")
		}
	}

	// delete UID from keyDB
	if err := ce.keyDB.DeletePrivateUID(msg); err != nil {
		return err
	}
	return nil
}

// list UIDs shows all own (mapped) users IDs on outfp.
func (ce *CryptEngine) listUIDs(outfp *os.File) error {
	ids, err := ce.keyDB.GetPrivateIdentities()
	if err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Fprintln(outfp, id)
	}
	return nil
}
