// Package smtpclient wraps pkg/smtp to make it easy to use
package smtpclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/rand"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/mutecomm/mute/util/times"
)

var (
	// ErrNoHost is returned if no delivery host could be found
	ErrNoHost = errors.New("smtpclient: No host")
	// ErrNoTLS is returned if TLS was not offered though it was expected
	ErrNoTLS = errors.New("smtpclient: No TLS")
	// ErrNoAuth is returned if authentication was not offered though it was expected
	ErrNoAuth = errors.New("smtpclient: No AUTH")
	// ErrFinal is returned if a resend-attempt will fail
	ErrFinal = errors.New("smtpclient: Final error")
	// ErrRetry is retured if a resend-attempt might work
	ErrRetry = errors.New("smtpclient: Retry")
)

// LookupMX returns the primary MX for a domain
func LookupMX(domain string) string {
	if domain == "" {
		return ""
	}
	mx, err := net.LookupMX(domain)
	if err != nil {
		return domain
	}
	if len(mx) == 0 {
		return ""
	}
	l := int32(len(mx))
	rand.Seed(times.NowNano())
	p := rand.Int31() % l
	return mx[p].Host[:len(mx[p].Host)-1]
}

// MailClient implements a trivial SMTP client
type MailClient struct {
	HeloHost       string // How to identify in greetings, can be ""
	CACert         []byte // CA Certificate to enforce. Can be nil to not enforce TLS
	NoSSL          bool   // disable all SSL
	User, Password string // Authentication
	Port           int    // SMTP port, defaults to 25
	SmartHost      string // Smarthost, for sending via a destination independent smarthost
	LastError      error  // Last error encountered
	LastErrorCode  int    // Last SMTP error code
}

// GetMailDomain returns the domain of an email address
func GetMailDomain(addr string) string {
	address, err := mail.ParseAddress(addr)
	if err != nil {
		return ""
	}
	pos := strings.Index(address.Address, "@")
	if pos > 0 && len(address.Address) > pos+2 {
		return address.Address[pos+1:]
	}
	return ""
}

// ParseError parses an SMTP error and sets LastError accordingly and returns a matching upstream error
func (mc *MailClient) parseError(err error) error {
	if err == nil {
		return nil
	}
	mc.LastError = err
	str := err.Error()
	str = strings.Trim(str, " \t")
	pos := strings.Index(str, " ")
	if pos > 0 {
		code := str[0:pos]
		codeNum, err := strconv.Atoi(code)
		if err == nil {
			mc.LastErrorCode = codeNum
			if codeNum >= 500 {
				return ErrFinal
			}
			return ErrRetry
		}
	}
	return err
}

// SendMail will send mail to "to" using "from" as sender. Mail must already correctly formatted since SendMail only
// takes care of SMTP. Errors returned signal if a retry might work.
func (mc *MailClient) SendMail(to, from string, mail []byte) error {
	var err error
	var host string
	if mc == nil {
		mc = new(MailClient)
	}
	if mc.Port == 0 {
		mc.Port = 25
	}
	if mc.SmartHost != "" {
		host = mc.SmartHost
	} else {
		host = LookupMX(GetMailDomain(to))
	}
	if host == "" {
		mc.LastError = ErrNoHost
		return ErrFinal
	}
	address := host + ":" + strconv.Itoa(mc.Port)
	client, err := smtp.Dial(address)
	if err != nil {
		mc.parseError(err)
		return ErrRetry
	}
	defer client.Close()
	if mc.HeloHost != "" {
		client.Hello(mc.HeloHost)
	}
	// Do TLS if offered
	if !mc.NoSSL {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsconfig := new(tls.Config)
			tlsconfig.ServerName = host
			if mc.CACert != nil {
				// setup tls.config
				tlsconfig.RootCAs = x509.NewCertPool()
				ok := tlsconfig.RootCAs.AppendCertsFromPEM(mc.CACert)
				if !ok {
					mc.parseError(ErrNoTLS)
					return ErrFinal
				}
			}
			err = client.StartTLS(tlsconfig)
			if err != nil {
				return mc.parseError(err)
			}
		} else if mc.CACert != nil {
			mc.parseError(ErrNoTLS)
			return ErrFinal
		}
	}
	if !(mc.User == "" || mc.Password == "") {
		var ok bool
		var ext string
		var auth smtp.Auth
		if ok, ext = client.Extension("AUTH"); !ok {
			mc.parseError(ErrNoAuth)
			return ErrFinal
		}
		if strings.Contains(ext, "CRAM-MD5") {
			auth = smtp.CRAMMD5Auth(mc.User, mc.Password)
		} else if strings.Contains(ext, "PLAIN") {
			auth = smtp.PlainAuth("", mc.User, mc.Password, host)
		} else {
			mc.parseError(ErrNoAuth)
			return ErrFinal
		}
		err := client.Auth(auth)
		if err != nil {
			return mc.parseError(err)
		}
	}
	err = client.Mail(from)
	if err != nil {
		return mc.parseError(err)
	}
	err = client.Rcpt(to)
	if err != nil {
		return mc.parseError(err)
	}
	w, err := client.Data()
	if err != nil {
		return mc.parseError(err)
	}
	_, err = w.Write(mail)
	if err != nil {
		client.Reset()
		return mc.parseError(err)
	}
	err = w.Close()
	if err != nil {
		client.Reset()
		return mc.parseError(err)
	}
	err = client.Quit()
	return mc.parseError(err)
}
