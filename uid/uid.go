// Package uid defines user IDs in Mute and necessary long-term and short-term
// key material.
package uid

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"

	"github.com/fatih/structs"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/uid/identity"
	"github.com/mutecomm/mute/util/times"
)

// The current version of the protocol.
const ProtocolVersion = "1.0"

// PFSPreference representes a PFS preference.
type PFSPreference int

const (
	// Strict PFS preference.
	Strict PFSPreference = iota
	// Mandatory PFS preference.
	Mandatory
	// Optional PFS preference.
	Optional
)

var pfsPreferences = []string{
	"strict",
	"mandatory",
	"optional",
}

// String returns the string representation of pfsPreference.
func (pfsPreference PFSPreference) String() string {
	return pfsPreferences[pfsPreference]
}

type preferences struct {
	FORWARDSEC   string   // forward security preference
	CIPHERSUITES []string // list of ciphersuites, ordered from most preferred to least preferred.
}

type chainlink struct {
	URI         []string // URI(s) of the foreign key hashchain
	LAST        string   // last entry of the foreign key hashchain
	AUTHORATIVE bool
	DOMAINS     []string // list of domains that are served currently
	IDENTITY    string   // own Identity in the foreign key hashchain
}

type uidContent struct {
	VERSION     string      // the protocol version
	MSGCOUNT    uint64      // must increase for each message
	NOTAFTER    uint64      // time after which the key(s) should not be used anymore
	NOTBEFORE   uint64      // time before which the key(s) should not be used yet
	MIXADDRESS  string      // fully qualified address of mix to use as last hop
	NYMADDRESS  string      // a valid NymAddress
	IDENTITY    string      // identity/pseudonym claimed (including domain)
	SIGKEY      KeyEntry    // used to sign UIDContent and to authenticate future UIDMessages
	PUBKEYS     []KeyEntry  // for static key content confidentiality
	SIGESCROW   KeyEntry    // used to optionally authenticate future UIDMessage
	LASTENTRY   string      // last known key hashchain entry
	REPOURIS    []string    // URIs of KeyInit Repositories to publish KeyInit messages
	PREFERENCES preferences // PFS preference
	CHAINLINK   chainlink   // used only for "linking chains and key repositories"
}

// Message is a UIDMessage to be sent from user to key server.
// It represents a user ID in Mute and contains long-term keys.
type Message struct {
	UIDCONTENT uidContent
	// Signature over UIDContent by previous SIGESCROW.
	ESCROWSIGNATURE string
	// Signature over UIDContent by previous SIGKEY.
	USERSIGNATURE string
	// Signature over UIDContent by current SIGKEY.
	SELFSIGNATURE string
	// Signature over UIDContent by key server SIGESCROW in the case of
	// authorative keyserver links.
	// Must be zero unless an authorative link entry.
	LINKAUTHORITY string
}

// Entry describes a key server entry.
type Entry struct {
	UIDMESSAGEENCRYPTED string // encrypted version of UIDMessage
	HASHCHAINENTRY      string // corresponding key hashchain entry
	HASHCHAINPOS        uint64 // position of key hashchain entry
}

// A MessageReply indicates a successful reply from key server.
type MessageReply struct {
	ENTRY           Entry
	SERVERSIGNATURE string // signature over Entry by keyserver's signature key
}

// Create creates a new UID message for the given userID and self-signs it.
// It automatically creates all necessary keys. If sigescrow is true,  an
// escrow key is included in the created UID message.
// Necessary randomness is read from rand.
func Create(
	userID string,
	sigescrow bool,
	mixaddress, nymaddress string,
	pfsPreference PFSPreference,
	rand io.Reader,
) (*Message, error) {
	var msg Message
	var err error
	// check user ID (identity)
	if err := identity.IsMapped(userID); err != nil {
		return nil, err
	}
	msg.UIDCONTENT.MSGCOUNT = 0                            // TODO: first UIDMessage
	msg.UIDCONTENT.NOTAFTER = uint64(times.OneYearLater()) // TODO: make this settable!
	msg.UIDCONTENT.NOTBEFORE = 0                           // TODO: make this settable
	if pfsPreference == Optional {
		msg.UIDCONTENT.MIXADDRESS = mixaddress
		msg.UIDCONTENT.NYMADDRESS = nymaddress
	} else {
		msg.UIDCONTENT.MIXADDRESS = ""
		msg.UIDCONTENT.NYMADDRESS = ""
	}
	msg.UIDCONTENT.IDENTITY = userID
	if err = msg.UIDCONTENT.SIGKEY.initSigKey(rand); err != nil {
		return nil, err
	}
	msg.UIDCONTENT.PUBKEYS = make([]KeyEntry, 1)
	if err := msg.UIDCONTENT.PUBKEYS[0].InitDHKey(rand); err != nil {
		return nil, err
	}
	if sigescrow {
		if err = msg.UIDCONTENT.SIGESCROW.initSigKey(rand); err != nil {
			return nil, err
		}
	}
	// TODO: LASTENTRY
	// TODO: REPOURIS
	msg.UIDCONTENT.PREFERENCES.FORWARDSEC = pfsPreference.String()
	msg.UIDCONTENT.PREFERENCES.CIPHERSUITES = []string{DefaultCiphersuite}
	// TODO: CHAINLINK

	// TODO: ESCROWSIGNATURE
	// TODO: USERSIGNATURE

	selfsig := msg.UIDCONTENT.SIGKEY.ed25519Key.Sign(msg.UIDCONTENT.JSON())
	msg.SELFSIGNATURE = base64.Encode(selfsig)

	// TODO: LINKAUTHORITY
	return &msg, nil
}

// Encrypt encryptes the given UID message.
func (msg *Message) Encrypt() (UIDHash, UIDIndex []byte, UIDMessageEncrypted string) {
	Message := msg.JSON()
	// Calculate hash: UIDHash = sha256(UIDMessage)
	UIDHash = cipher.SHA256(Message)
	// Calculate hash: UIDIndex = sha256(UIDHash)
	UIDIndex = cipher.SHA256(UIDHash)
	// Encrypt UIDMessage: UIDMessageEncrypted = UIDIndex | nonce | aes_ctr(nonce, key=UIDHash, UIDMessage)
	enc := cipher.AES256CTREncrypt(UIDHash, Message, cipher.RandReader)
	uidEnc := make([]byte, sha256.Size+len(enc))
	copy(uidEnc, UIDIndex)
	copy(uidEnc[sha256.Size:], enc)
	UIDMessageEncrypted = base64.Encode(uidEnc)
	return
}

// Identity returns the identity of the UID message msg.
func (msg *Message) Identity() string {
	return msg.UIDCONTENT.IDENTITY
}

// SigKeyHash returns the SIGKEYHASH which corresponds to the given UID message.
func (msg *Message) SigKeyHash() (string, error) {
	return SigKeyHash(msg.UIDCONTENT.SIGKEY.HASH)
}

// SigPubKey returns the public signature key which corresponds to the given
// UID message.
func (msg *Message) SigPubKey() string {
	return msg.UIDCONTENT.SIGKEY.PUBKEY
}

// PubHash returns the public key hash which corresponds to the given UID message.
func (msg *Message) PubHash() string {
	// at the moment we only support one ciphersuite, therefore the index is hard-coded
	// TODO: check function
	return msg.UIDCONTENT.PUBKEYS[0].HASH
}

// PubKey returns the public key for the given UID message.
func (msg *Message) PubKey() *KeyEntry {
	// at the moment we only support one ciphersuite, therefore the index is hard-coded
	// TODO: check function
	return &msg.UIDCONTENT.PUBKEYS[0]
}

// PublicKey decodes the 32-byte public key from the given UID message and
// returns it.
func (msg *Message) PublicKey() (*[32]byte, error) {
	publicKey, err := base64.Decode(msg.PubKey().PUBKEY)
	if err != nil {
		return nil, err
	}
	// TODO: use other APIs from stdlib which do not require copy and panic
	var pk [32]byte
	if len(publicKey) != 32 {
		panic("uid: len(publicKey) != 32")
	}
	copy(pk[:], publicKey)
	return &pk, nil
}

// SigKeyHash returns the SIGKEYHASH which corresponds to the sigPubKey.
func SigKeyHash(sigPubKey string) (string, error) {
	keyHash, err := base64.Decode(sigPubKey)
	if err != nil {
		return "", err
	}
	return base64.Encode(cipher.SHA512(keyHash)), nil
}

// CreateReply creates MessageReply.
func CreateReply(
	UIDMessageEncrypted, HCEntry string,
	HCPos uint64,
	sigKey *cipher.Ed25519Key,
) *MessageReply {
	// Construct Entry from hcEntry, hcPos, UIDMessageEncrypted
	entry := Entry{
		UIDMESSAGEENCRYPTED: UIDMessageEncrypted,
		HASHCHAINENTRY:      HCEntry,
		HASHCHAINPOS:        HCPos,
	}

	// Sign Entry by Key Server's key pkey: serverSig = sign(pkey, Entry)
	serverSig := sigKey.Sign(entry.json())

	// Construct MessageReply from Entry, serverSig
	return &MessageReply{
		ENTRY:           entry,
		SERVERSIGNATURE: base64.Encode(serverSig),
	}
}

// NewJSON returns a new UIDMessage initialized with the parameters given in
// the JSON uid string.
func NewJSON(uid string) (*Message, error) {
	var msg Message
	if err := json.Unmarshal([]byte(uid), &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// NewJSONReply returns a new MessageReply initialized with the parameters
// given in the JSON uid string.
func NewJSONReply(uid string) (*MessageReply, error) {
	var reply MessageReply
	if err := json.Unmarshal([]byte(uid), &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func marshalSorted(strct interface{}) []byte {
	// convert the struct to map before the JSON encoding, because maps are
	// automatically sorted and structs are not
	m := structs.Map(strct)
	jsn, err := json.Marshal(m)
	if err != nil {
		// There should be not way this can happen, but better less than 100%
		// test coverage than an uncaught error.
		panic(log.Critical(err))
	}
	return jsn
}

// JSON encodes uidContent as a JSON string according to the specification.
func (content *uidContent) JSON() []byte {
	return marshalSorted(content)
}

// JSON encodes UIDMessage as a JSON string according to the specification.
func (msg *Message) JSON() []byte {
	return marshalSorted(msg)
}

// json encodes entry as a JSON string according to the specification.
func (entry *Entry) json() []byte {
	return marshalSorted(entry)
}

// JSON encodes MessageReply as a JSON string according to the specification.
func (reply *MessageReply) JSON() []byte {
	return marshalSorted(reply)
}

// VerifySelfSig verifies that the self-signature of UIDMessage is valid.
func (msg *Message) VerifySelfSig() error {
	var ed25519Key cipher.Ed25519Key
	// get content
	content := msg.UIDCONTENT.JSON()
	// get self-signature
	selfsig, err := base64.Decode(msg.SELFSIGNATURE)
	if err != nil {
		return err
	}
	// create ed25519 key
	pubKey, err := base64.Decode(msg.UIDCONTENT.SIGKEY.PUBKEY)
	if err != nil {
		return err
	}
	if err := ed25519Key.SetPublicKey(pubKey); err != nil {
		return err
	}
	// verify self-signature
	if !ed25519Key.Verify(content, selfsig) {
		return log.Error(ErrInvalidSelfSig)
	}
	return nil
}

// VerifyUserSig verifies that the user-signature of UIDMessage is valid.
func (msg *Message) VerifyUserSig(preMsg *Message) error {
	var ed25519Key cipher.Ed25519Key
	// check message counter
	if preMsg.UIDCONTENT.MSGCOUNT+1 != msg.UIDCONTENT.MSGCOUNT {
		return log.Error(ErrIncrement)
	}
	// get content
	content := msg.UIDCONTENT.JSON()
	// get self-signature
	selfsig, err := base64.Decode(msg.USERSIGNATURE)
	if err != nil {
		return err
	}
	// create ed25519 key
	pubKey, err := base64.Decode(preMsg.UIDCONTENT.SIGKEY.PUBKEY)
	if err != nil {
		return err
	}
	if err := ed25519Key.SetPublicKey(pubKey); err != nil {
		return err
	}
	// verify self-signature
	if !ed25519Key.Verify(content, selfsig) {
		return log.Error(ErrInvalidUserSig)
	}
	return nil
}

// PrivateSigKey returns the base64 encoded private signature key of the UID
// message.
func (msg *Message) PrivateSigKey() string {
	return base64.Encode(msg.UIDCONTENT.SIGKEY.PrivateKey64()[:])
}

// PublicSigKey32 returns the 32-byte public signature key of the given UID
// message and returns it.
func (msg *Message) PublicSigKey32() *[32]byte {
	return msg.UIDCONTENT.SIGKEY.PublicKey32()
}

// PrivateSigKey64 returns the 64-byte private signature key of the given UID
// message.
func (msg *Message) PrivateSigKey64() *[64]byte {
	return msg.UIDCONTENT.SIGKEY.PrivateKey64()
}

// SetPrivateSigKey sets the private signature key to the given base64 encoded
// privkey string.
func (msg *Message) SetPrivateSigKey(privkey string) error {
	key, err := base64.Decode(privkey)
	if err != nil {
		return err
	}
	return msg.UIDCONTENT.SIGKEY.setPrivateKey(key)
}

// PrivateEncKey returns the base64 encoded private encryption key of the
// given UID message.
func (msg *Message) PrivateEncKey() string {
	return base64.Encode(msg.UIDCONTENT.PUBKEYS[0].PrivateKey32()[:])
}

// PublicEncKey32 decodes the 32-byte public encryption key of the given UID
// message and returns it.
func (msg *Message) PublicEncKey32() *[32]byte {
	return msg.UIDCONTENT.PUBKEYS[0].PublicKey32()
}

// PrivateEncKey32 decodes the 32-byte private encryption key of the given UID
// message and returns it.
func (msg *Message) PrivateEncKey32() *[32]byte {
	return msg.UIDCONTENT.PUBKEYS[0].PrivateKey32()
}

// SetPrivateEncKey sets the private encryption key to the given base64 encoded
// privkey string.
func (msg *Message) SetPrivateEncKey(privkey string) error {
	key, err := base64.Decode(privkey)
	if err != nil {
		return err
	}
	return msg.UIDCONTENT.PUBKEYS[0].setPrivateKey(key)
}

// Localpart returns the localpart of the uid identity.
func (msg *Message) Localpart() string {
	lp, _, err := identity.Split(msg.UIDCONTENT.IDENTITY)
	if err != nil {
		// UID messages have to be valid
		panic(log.Critical(err))
	}
	return lp
}

// Domain returns the domain of the uid identity.
func (msg *Message) Domain() string {
	_, domain, err := identity.Split(msg.UIDCONTENT.IDENTITY)
	if err != nil {
		// UID messages have to be valid
		panic(log.Critical(err))
	}
	return domain
}

// Update generates an updated version of the given UID message, signs it with
// the private signature key, and returns it.
func (msg *Message) Update(rand io.Reader) (*Message, error) {
	var up Message
	// copy
	up = *msg
	// increase counter
	up.UIDCONTENT.MSGCOUNT++
	// update signature key
	if err := up.UIDCONTENT.SIGKEY.initSigKey(rand); err != nil {
		return nil, err
	}
	err := up.UIDCONTENT.PUBKEYS[0].setPrivateKey(msg.UIDCONTENT.PUBKEYS[0].PrivateKey32()[:])
	if err != nil {
		return nil, err
	}
	// self-signature
	selfsig := up.UIDCONTENT.SIGKEY.ed25519Key.Sign(up.UIDCONTENT.JSON())
	up.SELFSIGNATURE = base64.Encode(selfsig)
	// sign with previous key
	prevsig := msg.UIDCONTENT.SIGKEY.ed25519Key.Sign(up.UIDCONTENT.JSON())
	up.USERSIGNATURE = base64.Encode(prevsig)
	return &up, nil
}

// SignNonce signs the current time as nonce and returns it.
func (msg *Message) SignNonce() (nonce uint64, signature string) {
	nonce = uint64(times.Now())
	signature = base64.Encode(msg.UIDCONTENT.SIGKEY.ed25519Key.Sign(encode.ToByte8(nonce)))
	return
}

// VerifyNonce verifies the nonce signature with the given sigPubKey.
func VerifyNonce(sigPubKey string, nonce uint64, signature string) error {
	var ed25519Key cipher.Ed25519Key
	sig, err := base64.Decode(signature)
	if err != nil {
		return err
	}
	pubKey, err := base64.Decode(sigPubKey)
	if err != nil {
		return err
	}
	if err := ed25519Key.SetPublicKey(pubKey); err != nil {
		return err
	}
	if !ed25519Key.Verify(encode.ToByte8(nonce), sig) {
		return log.Error(ErrInvalidNonceSig)
	}
	return nil
}

// Decrypt decrypts the message reply and returns the resulting UIDIndex and
// UIDMesssage.
func (reply *MessageReply) Decrypt(UIDHash []byte) ([]byte, *Message, error) {
	UIDMessageEncrypted, err := base64.Decode(reply.ENTRY.UIDMESSAGEENCRYPTED)
	if err != nil {
		return nil, nil, log.Error(err)
	}
	UIDIndex := UIDMessageEncrypted[:sha256.Size]
	enc := UIDMessageEncrypted[sha256.Size:]
	Message := cipher.AES256CTRDecrypt(UIDHash, enc)
	uid, err := NewJSON(string(Message))
	if err != nil {
		return nil, nil, log.Error(err)
	}
	return UIDIndex, uid, nil
}

// VerifySrvSig verifies that the server-signature of MessageReply is valid.
func (reply *MessageReply) VerifySrvSig(msg *Message, srvPubKey string) error {
	// make sure messages match
	UIDHash, UIDIndex, _ := msg.Encrypt()
	idx, msg, err := reply.Decrypt(UIDHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(idx, UIDIndex) {
		return log.Error(ErrMsgMismatch)
	}
	if !bytes.Equal(msg.JSON(), msg.JSON()) {
		return log.Error(ErrMsgMismatch)
	}
	// verify server signature
	var ed25519Key cipher.Ed25519Key
	// get content
	content := reply.ENTRY.json()
	// get server-signature
	sig, err := base64.Decode(reply.SERVERSIGNATURE)
	if err != nil {
		return log.Error(err)
	}
	// create ed25519 key
	pubKey, err := base64.Decode(srvPubKey)
	if err != nil {
		return log.Error(err)
	}
	if err := ed25519Key.SetPublicKey(pubKey); err != nil {
		return err
	}
	// verify server-signature
	if !ed25519Key.Verify(content, sig) {
		return log.Error(ErrInvalidSrvSig)
	}
	return nil
}
