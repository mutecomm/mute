// Package jsonclient contains a JSON-RPC over HTTPS client for Mute.
package jsonclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"

	"github.com/gorilla/rpc/v2/json2"
)

var (
	// ErrCertLoad signals a loading error of the certificate
	ErrCertLoad = errors.New("json: Certificate load failed")
)

// URLClient is a client for JSON-RPC over HTTPS calls.
type URLClient struct {
	transport *http.Transport
	curl      string
}

// New creates a new JSON-RPC over HTTPS client which uses the given
// certificate file to communicate with the server if the scheme of the URL is https.
func New(URL string, cert []byte) (*URLClient, error) {
	var pool *x509.CertPool
	transport := new(http.Transport)
	urlparsed, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	if urlparsed.Scheme == "https" {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cert) {
			return nil, ErrCertLoad
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &URLClient{transport: transport, curl: URL}, nil
}

// JSONRPCRequest calls the given method via JSON-RPC over HTTPS.
// It supplies the given JSON args to the called method.
func (c *URLClient) JSONRPCRequest(method string, args interface{}) (map[string]interface{}, error) {
	if args == nil {
		// a nil argument would trigger an error, send empty object instead
		args = struct{}{}
	}
	buf, err := json2.EncodeClientRequest(method, args)
	if err != nil {
		return nil, err
	}
	// create new client with activated TLS
	client := &http.Client{Transport: c.transport}
	body := bytes.NewBuffer(buf)
	// make HTTP request
	request, err := http.NewRequest("POST", c.curl, body)
	if err != nil {
		return nil, err
	}
	defer request.Body.Close()
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	reply := make(map[string]interface{})
	err = json2.DecodeClientResponse(resp.Body, &reply)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return reply, nil
}
