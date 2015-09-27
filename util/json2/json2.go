// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package json2 contains a JSON-RPC over HTTPS client for Mute.
package json2

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/rpc/v2/json2"
	"github.com/mutecomm/mute/log"
)

// Client is a client for JSON-RPC over HTTPS calls.
type Client struct {
	transport  *http.Transport
	host, port string
}

// NewClient creates a new JSON-RPC over HTTPS client which uses the given
// certificate file to communicate with the server.
func NewClient(certFile, host, port string) (*Client, error) {
	// create new transport config with activated TLS
	cf, err := os.Open(certFile)
	if err != nil {
		return nil, err
	}
	defer cf.Close()
	cert, err := ioutil.ReadAll(cf)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return nil, log.Errorf("could not parse certificate file '%s'", certFile)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		// TODO: disable compression?
		// DisableCompression: true,
	}
	return &Client{transport: transport, host: host, port: port}, nil
}

// JSONRPCRequest calls the given method via JSON-RPC over HTTPS.
// It supplies the given JSON args to the called method.
func (c *Client) JSONRPCRequest(method string, args interface{}) (map[string]interface{}, error) {
	if args == nil {
		// a nil argument would trigger an error, send empty object instead
		args = struct{}{}
	}
	buf, err := json2.EncodeClientRequest(method, args)
	if err != nil {
		return nil, log.Error(err)
	}
	// create new client with activated TLS
	client := &http.Client{Transport: c.transport}
	body := bytes.NewBuffer(buf)
	// make HTTP request
	request, err := http.NewRequest("POST", "https://"+c.host+c.port+"/", body)
	if err != nil {
		return nil, log.Error(err)
	}
	defer request.Body.Close()
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return nil, log.Error(err)
	}
	reply := make(map[string]interface{})
	err = json2.DecodeClientResponse(resp.Body, &reply)
	if err != nil {
		return nil, log.Error(err)
	}
	resp.Body.Close()
	return reply, nil
}
