package mixcrypt

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/mutecomm/mute/mix/nymaddr"
)

// ClientMixHeader contains fields meant by the Client for the Mix
type ClientMixHeader struct {
	MessageType                    int32 // The type of the message (forward/relay). Forward does not have NymAddress/RevokeID set
	SenderMinDelay, SenderMaxDelay int32
	Token                          []byte // Payment Token
	Address                        []byte // NymAddress for relay, next mix for forward
	RevokeID                       []byte // Revokation secret
}

// ReceiveStruct contains data gathered from receiving a message
type ReceiveStruct struct {
	MixHeader         *ClientMixHeader
	NymAddress        *nymaddr.Address
	NymAddressPrivate *nymaddr.AddressPrivate
	UniqueTest        []UniquenessData
	Message           []byte
}

// UniquenessData contains the hash and expire time for a uniqueness-check
type UniquenessData struct {
	Hash   []byte
	Expire int64
}

// Marshal a ClientMixHeader
func (cl ClientMixHeader) Marshal() []byte {
	if cl.Token == nil {
		cl.Token = []byte{0x00}
	}
	if cl.RevokeID == nil || cl.MessageType == MessageTypeForward {
		cl.RevokeID = []byte{0x00}
	}
	d, err := asn1.Marshal(cl)
	if err != nil {
		panic(err) // Should never happen
	}
	ret := make([]byte, len(d)+2)
	binary.BigEndian.PutUint16(ret[0:2], uint16(len(d)))
	copy(ret[2:], d)
	return ret
}

// Unmarshal a binary ClientMixHeader. Returns header length to allow working with full-message slices
func (cl *ClientMixHeader) Unmarshal(d []byte) (header *ClientMixHeader, headerlen uint16, err error) {
	if len(d) < 3 {
		return nil, 0, ErrTooShort
	}
	if cl == nil {
		cl = new(ClientMixHeader)
	}
	lenB := binary.BigEndian.Uint16(d[0:2]) + 2
	if len(d) < int(lenB) {
		return nil, lenB, ErrTooShort
	}
	_, err = asn1.Unmarshal(d[2:lenB], cl)
	if err != nil {
		return nil, lenB, err
	}
	if cl.Token[0] == 0x00 && len(cl.Token) == 1 {
		cl.Token = nil
	}
	if (cl.RevokeID[0] == 0x00 && len(cl.RevokeID) == 1) || cl.MessageType == MessageTypeForward {
		cl.RevokeID = nil
	}
	return cl, lenB, nil
}

// NewForwardMessage creates a new message with type MessageTypeForward. Uses ClientMixHeader SenderMinDelay,SenderMaxDelay,Token
func (cl *ClientMixHeader) NewForwardMessage(NextHop string, NextHopKey *[KeySize]byte, msg []byte) (message []byte, deliverAddress string, err error) {
	if cl == nil {
		cl = new(ClientMixHeader)
	}
	cl.MessageType = MessageTypeForward
	cl.Address = []byte(NextHop)
	header := cl.Marshal()
	messageC := make([]byte, len(header)+len(msg))
	copy(messageC[0:len(header)], header)
	copy(messageC[len(header):], msg)
	msgEncrypted, err := Encrypt(NextHopKey, nil, messageC)
	return msgEncrypted, NextHop, err
}

// NewRelayMessage creates a new message with type MessageTypeRelay. Uses ClientMixHeader SenderMinDelay,SenderMaxDelay,Token. Sets revokeID
func (cl *ClientMixHeader) NewRelayMessage(NymAddress []byte, msg []byte) (message []byte, deliverAddress string, err error) {
	if cl == nil {
		cl = new(ClientMixHeader)
	}
	address, err := nymaddr.ParseAddress(NymAddress)
	if err != nil {
		return nil, "", err
	}
	NextHopKey := new([KeySize]byte)
	copy(NextHopKey[:], address.MixPubKey)
	cl.MessageType = MessageTypeRelay
	cl.Address = NymAddress
	revokeID, _ := genNonce()
	cl.RevokeID = revokeID[:]
	header := cl.Marshal()
	messageC := make([]byte, len(header)+len(msg))
	copy(messageC[0:len(header)], header)
	copy(messageC[len(header):], msg)
	msgEncrypted, err := Encrypt(NextHopKey, nil, messageC)
	return msgEncrypted, string(address.MixAddress), err
}

func mkHash(d []byte) []byte {
	x := sha256.Sum256(d)
	return x[:]
}

// ReceiveMessage receives a Client-Mix message
func ReceiveMessage(lookupKey KeyFunc, message []byte) (*ReceiveStruct, error) {
	// var uniqueDat []UniquenessData
	var rstr ReceiveStruct
	var lenB uint16
	decMessage, err := Decrypt(lookupKey, message)
	if err != nil {
		return nil, err
	}
	rstr.MixHeader, lenB, err = new(ClientMixHeader).Unmarshal(decMessage)
	if err != nil {
		return nil, err
	}
	// Test Size
	msgLen := len(decMessage) - int(lenB)
	if rstr.MixHeader.MessageType == MessageTypeRelay && (msgLen < RelayMinSize || msgLen > RelayMaxSize) {
		fmt.Println(msgLen)
		return nil, ErrSize
	}
	if rstr.MixHeader.MessageType == MessageTypeForward && (msgLen < ForwardMinSize || msgLen > ForwardMaxSize) {
		return nil, ErrSize
	}
	// Uniqueness data collection
	if rstr.MixHeader.MessageType == MessageTypeRelay {
		rstr.NymAddress, err = nymaddr.ParseAddress(rstr.MixHeader.Address)
		if err != nil {
			return nil, err
		}
		rstr.NymAddressPrivate, err = rstr.NymAddress.GetMixData(nymaddr.KeyFunc(lookupKey))
		if err != nil {
			return nil, err
		}
		// First 256byte of message
		rstr.UniqueTest = append(rstr.UniqueTest, UniquenessData{
			Expire: rstr.NymAddressPrivate.Expire,
			Hash:   mkHash(decMessage[lenB : lenB+256]), // First 256 byte of message
		})
		if rstr.NymAddressPrivate.SingleUse {
			rstr.UniqueTest = append(rstr.UniqueTest, UniquenessData{
				Expire: rstr.NymAddressPrivate.Expire,
				Hash:   rstr.NymAddressPrivate.ReceiverPubKey,
			})
		}
	} else {
		rstr.UniqueTest = append(rstr.UniqueTest, UniquenessData{
			Expire: timeNow() + ExpireReceive,
			Hash:   mkHash(decMessage[lenB : lenB+256]), // First 256 byte of message
		})
	}
	rstr.Message = decMessage[lenB:]
	return &rstr, nil
}
