package client

import (
	"encoding/asn1"

	"github.com/mutecomm/mute/mix/mixcrypt"
	"github.com/mutecomm/mute/mix/smtpclient"
)

// MessageInput contains everything to describe an outgoing message.
type MessageInput struct {
	SenderMinDelay, SenderMaxDelay int32  // Mix settings
	Token                          []byte // Payment token
	NymAddress                     []byte // The nym-address of the recipient
	Message                        []byte // The message itself
	SMTPPort                       int    // Port on which to do SMTP. Can be empty
	SmartHost                      string // Server to which to send. Can be empty
	CACert                         []byte // CACert for TLS verification on SMTP
}

// MessageOutput contains the result of a develivery attempt.
type MessageOutput struct {
	Message   []byte // Nil on success
	To        string // Empty on success
	From      string // Empty on success
	RevokeID  []byte // Set if develivery was attempted
	SMTPPort  int    // Port on which to do SMTP. Can be empty
	SmartHost string // Server to which to send. Can be empty
	CACert    []byte // CACert for TLS verification on SMTP
	Error     error  // Non-Nil on error
	Resend    bool   // Bool if sending might help
}

// Create a message described in messageInput.
func (mi MessageInput) Create() (messageOut *MessageOutput) {
	var msgInter []byte
	messageOut = new(MessageOutput)
	messageOut.From = DefaultSender
	cl := new(mixcrypt.ClientMixHeader)
	cl.SenderMinDelay, cl.SenderMaxDelay = mi.SenderMinDelay, mi.SenderMaxDelay
	cl.Token = mi.Token
	msgInter, messageOut.To, messageOut.Error = cl.NewRelayMessage(mi.NymAddress, mi.Message)
	if messageOut.Error != nil {
		return messageOut
	}
	messageOut.RevokeID = cl.RevokeID
	messageOut.Message = WriteMail(messageOut.From, messageOut.To, msgInter)
	messageOut.SMTPPort = mi.SMTPPort
	messageOut.SmartHost = mi.SmartHost
	messageOut.CACert = mi.CACert
	messageOut.Resend = true
	return messageOut
}

// Deliver a message countained in messageOutput.
// Can be used like this:
//
//     messageOut, err := messageIn.Create().Deliver()
//     for err!=nil && messageOut.Resend {
//         cache := messageOut.Marshal()
//         //...wait/stop/quit/sleep -> restart/wakeup
//         messageOut, err = cache.UnMarshal().Deliver()
//     }
//     //...done
//
func (mo *MessageOutput) Deliver() (messageOut *MessageOutput, err error) {
	if mo == nil {
		return nil, ErrNIL
	}
	if mo.Resend {
		mailClient := smtpclient.MailClient{
			CACert:    mo.CACert,
			Port:      mo.SMTPPort,
			SmartHost: mo.SmartHost,
		}
		mo.Error = mailClient.SendMail(mo.To, mo.From, mo.Message)
		if mo.Error == nil {
			mo.Resend = false
			mo.Message = nil
			mo.To = ""
			mo.From = ""
			mo.SMTPPort = 0
			mo.SmartHost = ""
			mo.CACert = nil
			mo.Error = nil
		}
		if mo.Error == smtpclient.ErrFinal {
			mo.Resend = false
			mo.Error = mailClient.LastError
		}
		return mo, mo.Error
	}
	if mo.Message == nil {
		return mo, ErrAlreadySent
	}
	return mo, mo.Error
}

// MessageMarshalled contains a marshalled MessageOutput.
type MessageMarshalled []byte

// messageOutputForMarshal contains the result of a develivery attempt
type messageOutputForMarshal struct {
	Message   []byte // Nil on success
	To        string // Empty on success
	From      string // Empty on success
	RevokeID  []byte // Set if develivery was attempted
	SMTPPort  int    // Port on which to do SMTP. Can be empty
	SmartHost string // Server to which to send. Can be empty
	CACert    []byte // CACert for TLS verification on SMTP
	Error     string // Non-Nil on error
	Resend    bool   // Bool if sending might help
}

// Marshal a MessageOutput to a MessageMarshalled.
func (mo *MessageOutput) Marshal() MessageMarshalled {
	mom := messageOutputForMarshal{
		Message:   mo.Message,
		To:        mo.To,
		From:      mo.From,
		RevokeID:  mo.RevokeID,
		SMTPPort:  mo.SMTPPort,
		SmartHost: mo.SmartHost,
		CACert:    mo.CACert,
		Resend:    mo.Resend,
	}
	if mo.Error != nil {
		mom.Error = mo.Error.Error()
	} else {
		mom.Error = "nil"
	}
	d, err := asn1.Marshal(mom)
	if err != nil {
		return nil
	}
	return d
}

// Unmarshal a MessageMarshalled.
func (mm MessageMarshalled) Unmarshal() *MessageOutput {
	mom := new(messageOutputForMarshal)
	mo := new(MessageOutput)
	_, err := asn1.Unmarshal(mm, mom)
	if err != nil {
		mo.Error = err
		mo.Resend = false
	}
	mo.Message = mom.Message
	mo.To = mom.To
	mo.From = mom.From
	mo.RevokeID = mom.RevokeID
	mo.SMTPPort = mom.SMTPPort
	mo.SmartHost = mom.SmartHost
	mo.CACert = mom.CACert
	mo.Resend = mom.Resend
	if mom.Error != "" && mom.Error != "nil" {
		mo.Error = translateError(mom.Error)
	}
	return mo
}
