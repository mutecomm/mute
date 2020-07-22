// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package guardrpc implements calls from client -> server for token operations.
package guardrpc

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"

	"crypto/ed25519"
	"github.com/mutecomm/mute/serviceguard/common/constants"
	"github.com/mutecomm/mute/util/jsonclient"
)

var (
	// ErrParams is returned if a call returned bad parameters
	ErrParams = errors.New("guardrpc: bad RPC parameters")
)

// ServiceURL is the URL template for issuers. Notice the leading dot and trailing slash
var ServiceURL = constants.IssuerURL

// DefaultClientFactory is the default factory for new clients
var DefaultClientFactory = jsonclient.New

// RPCclient encapsulates a service-guard RPC client
type RPCclient struct {
	ClientFactory      func(string, []byte) (*jsonclient.URLClient, error)
	ServiceGuardCA     []byte   // The CA of the serviceguard, if any
	URL                *url.URL // The serviceguard URL template
	AuthUser, AuthPass string   // For optional authentication
}

// New returns a new RPCclient
func New(cacert []byte) (*RPCclient, error) {
	var err error
	rpcc := new(RPCclient)
	rpcc.ClientFactory = DefaultClientFactory
	rpcc.ServiceGuardCA = cacert
	rpcc.URL, err = url.Parse(ServiceURL)
	if err != nil {
		return nil, err
	}
	return rpcc, nil
}

func (rpc RPCclient) pubKeyToURL(pubKey *[ed25519.PublicKeySize]byte, internal bool) string {
	thost := ""
	tpath := ""
	if internal {
		thost = constants.IssuerInternalHost
		tpath = constants.IssuerInternalPathAddition
	}
	pk := hex.EncodeToString(pubKey[:])
	tempURL := *rpc.URL
	tempURL.Host = pk[0:48] + thost + tempURL.Host
	tempURL.Path = tempURL.Path + tpath + pk
	return tempURL.String()
}

// GetParams returns params from a service-guard identified by pubKey
func (rpc RPCclient) GetParams(pubKey *[ed25519.PublicKeySize]byte) ([]byte, error) {
	method := "ServiceGuard.GetParams"
	url := rpc.pubKeyToURL(pubKey, false)
	client, err := rpc.ClientFactory(url, rpc.ServiceGuardCA)
	if err != nil {
		return nil, err
	}
	data, err := client.JSONRPCRequest(method, nil)
	if err != nil {
		return nil, err
	}
	if _, ok := data["Packet"]; ok {
		params, err := base64.StdEncoding.DecodeString(data["Packet"].(string))
		if err != nil {
			return nil, err
		}
		return params, nil
	}
	return nil, ErrParams
}

// GetParamsInternal returns params from a service-guard identified by pubKey
func (rpc RPCclient) GetParamsInternal(pubKey *[ed25519.PublicKeySize]byte) ([]byte, error) {
	method := "ServiceGuardInternal.GetParams"
	url := rpc.pubKeyToURL(pubKey, true)
	client, err := rpc.ClientFactory(url, rpc.ServiceGuardCA)
	if err != nil {
		return nil, err
	}
	callParams := &struct{ AuthUser, AuthPass string }{AuthUser: rpc.AuthUser, AuthPass: rpc.AuthPass}
	data, err := client.JSONRPCRequest(method, callParams)
	if err != nil {
		return nil, err
	}
	if _, ok := data["Packet"]; ok {
		params, err := base64.StdEncoding.DecodeString(data["Packet"].(string))
		if err != nil {
			return nil, err
		}
		return params, nil
	}
	return nil, ErrParams
}

// Spend calls spend on the serviceguard
func (rpc RPCclient) Spend(pubKey *[ed25519.PublicKeySize]byte, packet []byte) (bool, error) {
	method := "ServiceGuard.Spend"
	url := rpc.pubKeyToURL(pubKey, false)
	client, err := rpc.ClientFactory(url, rpc.ServiceGuardCA)
	if err != nil {
		return false, err
	}
	packetEncoded := base64.StdEncoding.EncodeToString(packet)
	data, err := client.JSONRPCRequest(method, struct{ Packet string }{Packet: packetEncoded})
	if err != nil {
		return false, err
	}
	if _, ok := data["Status"]; ok {
		return data["Status"].(bool), nil
	}
	return false, ErrParams
}

// Reissue calls reissue on the serviceguard
func (rpc RPCclient) Reissue(pubKey *[ed25519.PublicKeySize]byte, packet []byte) ([]byte, []byte, error) {
	method := "ServiceGuard.Reissue"
	url := rpc.pubKeyToURL(pubKey, false)
	client, err := rpc.ClientFactory(url, rpc.ServiceGuardCA)
	if err != nil {
		return nil, nil, err
	}
	packetEncoded := base64.StdEncoding.EncodeToString(packet)
	data, err := client.JSONRPCRequest(method, struct{ Packet string }{Packet: packetEncoded})
	if err != nil {
		return nil, nil, err
	}
	if _, ok := data["Packet"]; !ok {
		return nil, nil, ErrParams
	}
	if _, ok := data["PubkeyUsed"]; !ok {
		return nil, nil, ErrParams
	}
	retpacket, err := base64.StdEncoding.DecodeString(data["Packet"].(string))
	if err != nil {
		return nil, nil, err
	}
	pubkeyUsed, err := base64.StdEncoding.DecodeString(data["PubkeyUsed"].(string))
	if err != nil {
		return nil, nil, err
	}
	return retpacket, pubkeyUsed, nil
}

// Issue calls issue on the serviceguard
func (rpc RPCclient) Issue(pubKey, owner *[ed25519.PublicKeySize]byte) ([]byte, []byte, error) {
	method := "ServiceGuardInternal.Issue"
	url := rpc.pubKeyToURL(pubKey, true)
	client, err := rpc.ClientFactory(url, rpc.ServiceGuardCA)
	if err != nil {
		return nil, nil, err
	}
	OwnerEncoded := ""
	if owner != nil {
		OwnerEncoded = hex.EncodeToString(owner[:])
	}
	data, err := client.JSONRPCRequest(method, struct{ Owner, AuthUser, AuthPass string }{
		Owner:    OwnerEncoded,
		AuthUser: rpc.AuthUser,
		AuthPass: rpc.AuthPass,
	})
	if err != nil {
		return nil, nil, err
	}
	if _, ok := data["Packet"]; !ok {
		return nil, nil, ErrParams
	}
	if _, ok := data["PubkeyUsed"]; !ok {
		return nil, nil, ErrParams
	}
	packet, err := base64.StdEncoding.DecodeString(data["Packet"].(string))
	if err != nil {
		return nil, nil, err
	}
	pubkeyUsed, err := base64.StdEncoding.DecodeString(data["PubkeyUsed"].(string))
	if err != nil {
		return nil, nil, err
	}
	return packet, pubkeyUsed, nil

}
