package mixcrypt

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/mutecomm/mute/mix/nymaddr"
)

// Send processes a ReceiveStruct and creates the outgoing message for it
func (rs ReceiveStruct) Send() ([]byte, string, error) {
	if rs.MixHeader.MessageType == MessageTypeRelay {
		return rs.sendRelay()
	}
	return rs.Message, string(rs.MixHeader.Address), nil
}

// sendRelay treats Receivestruct as input for a relay (mix -> client) message
func (rs ReceiveStruct) sendRelay() ([]byte, string, error) {
	headerContent, secret, err := rs.NymAddressPrivate.GetHeader()
	if err != nil {
		return nil, "", err
	}
	headerLen := len(headerContent)
	header := make([]byte, headerLen+2)
	binary.BigEndian.PutUint16(header[0:2], uint16(headerLen))
	copy(header[2:], headerContent)
	nonce := sha256.Sum256(headerContent)
	message, err := GCMEncrypt(nonce[:], secret, rs.Message)
	if err != nil {
		return nil, "", err
	}
	// BEGIN: Expand for multi-system
	if rs.NymAddressPrivate.System != 0x00 {
		return nil, "", ErrBadSystem
	}
	address := string(rs.NymAddressPrivate.Address) + MuteSystemDomain
	// END: Expand for multi-system
	return append(header, message...), address, nil
}

// ReceiveFromMix decrypts a message received from the mix
func ReceiveFromMix(receiveTemplate nymaddr.AddressTemplate, MailboxAddress, msg []byte) (decMessage, Nym []byte, err error) {
	if len(msg) < 2 {
		return nil, nil, ErrTooShort
	}
	headerLen := int(binary.BigEndian.Uint16(msg[0:2]))
	if len(msg) < 2+headerLen {
		return nil, nil, ErrTooShort
	}
	headerContent := msg[2 : 2+headerLen]
	nym, secret, err := receiveTemplate.GetPrivate(headerContent, MailboxAddress)
	if err != nil {
		return nil, nil, err
	}
	nonce := sha256.Sum256(headerContent)
	decMessage, err = GCMDecrypt(nonce[:], secret, msg[2+headerLen:])
	if err != nil {
		return nil, nil, err
	}
	return decMessage, nym, nil
}
