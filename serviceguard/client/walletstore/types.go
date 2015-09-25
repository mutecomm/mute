package walletstore

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"

	"github.com/mutecomm/mute/serviceguard/client"

	"github.com/agl/ed25519"
)

// TokenEntryDBGlobal is the global table for tokens
type TokenEntryDBGlobal struct {
	Hash         string // The unique token identifier
	Token        string // The token itself, marshalled
	OwnerPubKey  string // The Owner of the token
	OwnerPrivKey string // The private key of the owner, can be nil if specified for somebody else
	Renewable    bool   // The token can be renewed (at least once)
	CanReissue   bool   // Can this token be reissued?
	Usage        string // Usage of the token
	Expire       int64  // When the token will expire

	OwnedSelf bool // Is token owned by myself
	HasParams bool // Are params available for the token
	HasState  bool // Is state present?
}

// TokenEntryDBState contains processing state and params for a token
type TokenEntryDBState struct {
	Params          []byte // Params for the token, can be nil
	ServerPacket    []byte // Packet to be send to server
	BlindingFactors []byte // Local blinding factors
	NewOwnerPubKey  []byte // The Owner of the token after reissue
	NewOwnerPrivKey []byte // The private key of the new owner, can be nil if specified for somebody else
}

// encodeToken encodes a TokenEntry for database usage
func encodeToken(token *client.TokenEntry) (global *TokenEntryDBGlobal, state string) {
	global = &TokenEntryDBGlobal{
		Hash:        hex.EncodeToString(token.Hash),
		Token:       base64.StdEncoding.EncodeToString(token.Token),
		OwnerPubKey: base64.StdEncoding.EncodeToString(token.OwnerPubKey[:]),
		Renewable:   token.Renewable,
		CanReissue:  token.CanReissue,
		Usage:       token.Usage,
		Expire:      token.Expire,
	}
	if token.OwnerPrivKey != nil {
		global.OwnerPrivKey = base64.StdEncoding.EncodeToString(token.OwnerPrivKey[:])
		global.OwnedSelf = true
	}
	if token.Params != nil {
		global.HasParams = true
	}
	if token.ServerPacket != nil || token.BlindingFactors != nil || token.NewOwnerPrivKey != nil {
		global.HasState = true
	}

	if global.HasState || global.HasParams {
		stateS := TokenEntryDBState{
			Params:          token.Params,
			ServerPacket:    token.ServerPacket,
			BlindingFactors: token.BlindingFactors,
		}
		if token.NewOwnerPubKey != nil {
			stateS.NewOwnerPubKey = token.NewOwnerPubKey[:]
		}

		if token.NewOwnerPrivKey != nil {
			stateS.NewOwnerPrivKey = token.NewOwnerPrivKey[:]
		}
		stateM, err := asn1.Marshal(stateS)
		if err != nil {
			// This shouldnt happen ever
			panic("encodeToken state marshal: " + err.Error())
		}
		state = base64.StdEncoding.EncodeToString(stateM)
	}

	return global, state
}

// decodeToken decodes a database entry into a TokenEntry
func decodeToken(global *TokenEntryDBGlobal, state string) (token *client.TokenEntry, err error) {
	token = &client.TokenEntry{
		Renewable:  global.Renewable,
		CanReissue: global.CanReissue,
		Usage:      global.Usage,
		Expire:     global.Expire,
	}
	if token.Hash, err = hex.DecodeString(global.Hash); err != nil {
		return nil, err
	}
	if OwnerPubKey, err := base64.StdEncoding.DecodeString(global.OwnerPubKey); err == nil {
		token.OwnerPubKey = new([ed25519.PublicKeySize]byte)
		copy(token.OwnerPubKey[:], OwnerPubKey)
	} else {
		return nil, err
	}
	if token.Token, err = base64.StdEncoding.DecodeString(global.Token); err != nil {
		return nil, err
	}
	if global.OwnedSelf {
		if OwnerPrivKey, err := base64.StdEncoding.DecodeString(global.OwnerPrivKey); err == nil {
			token.OwnerPrivKey = new([ed25519.PrivateKeySize]byte)
			copy(token.OwnerPrivKey[:], OwnerPrivKey)
		} else {
			return nil, err
		}
	}
	if global.HasState || global.HasParams {
		stateM, err := base64.StdEncoding.DecodeString(state)
		if err != nil {
			return nil, err
		}
		stateS := new(TokenEntryDBState)
		_, err = asn1.Unmarshal(stateM, stateS)
		if err != nil {
			return nil, err
		}
		if stateS.Params != nil && len(stateS.Params) > 0 {
			token.Params = stateS.Params
		}
		if stateS.ServerPacket != nil && len(stateS.ServerPacket) > 0 {
			token.ServerPacket = stateS.ServerPacket
		}
		if stateS.BlindingFactors != nil && len(stateS.BlindingFactors) > 0 {
			token.BlindingFactors = stateS.BlindingFactors
		}
		if stateS.NewOwnerPrivKey != nil && len(stateS.NewOwnerPrivKey) == ed25519.PrivateKeySize {
			token.NewOwnerPrivKey = new([ed25519.PrivateKeySize]byte)
			copy(token.NewOwnerPrivKey[:], stateS.NewOwnerPrivKey)
		}
		if stateS.NewOwnerPubKey != nil && len(stateS.NewOwnerPubKey) == ed25519.PublicKeySize {
			token.NewOwnerPubKey = new([ed25519.PublicKeySize]byte)
			copy(token.NewOwnerPubKey[:], stateS.NewOwnerPubKey)
		}
	}

	return token, nil
}

// CacheData contains cached data for the wallet process
type CacheData struct {
	AuthToken  []byte
	AuthTries  int
	VerifyKeys [][ed25519.PublicKeySize]byte
}

// CacheDataDB contains a CacheData good for serialization
type CacheDataDB struct {
	AuthToken  []byte
	AuthTries  int
	VerifyKeys [][]byte
}

// Marshal a cachedata structure
func (cd *CacheData) Marshal() string {
	if cd == nil {
		cd = new(CacheData)
	}
	cdb := CacheDataDB{
		AuthToken:  cd.AuthToken,
		AuthTries:  cd.AuthTries,
		VerifyKeys: make([][]byte, 0, len(cd.VerifyKeys)),
	}
	for _, k := range cd.VerifyKeys {
		d := make([]byte, len(k))
		copy(d, k[:])
		cdb.VerifyKeys = append(cdb.VerifyKeys, d)
	}
	data, err := asn1.Marshal(cdb)
	if err != nil {
		// This should never happen
		panic("CacheData Marshal " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(data)
}

// Unmarshal CacheData
func (cd *CacheData) Unmarshal(d string) (*CacheData, error) {
	if cd == nil {
		cd = new(CacheData)
	}
	if cd.VerifyKeys == nil {
		cd.VerifyKeys = make([][ed25519.PublicKeySize]byte, 0)
	}
	db64, err := base64.StdEncoding.DecodeString(d)
	if err != nil {
		return nil, err
	}
	cdb := new(CacheDataDB)
	_, err = asn1.Unmarshal(db64, cdb)
	if err != nil {
		return nil, err
	}
	for _, key := range cdb.VerifyKeys {
		copyKey := new([ed25519.PublicKeySize]byte)
		copy(copyKey[:], key)
		cd.VerifyKeys = append(cd.VerifyKeys, *copyKey)
	}
	cd.AuthToken = cdb.AuthToken
	cd.AuthTries = cdb.AuthTries
	return cd, nil
}
