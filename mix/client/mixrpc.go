// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/mutecomm/mute/mix/mixaddr"
	"github.com/mutecomm/mute/mix/smtpclient"
)

// GetMixAddress is used to get the address of a mix rpc. It should only be
// changed for debugging purposes or if the routing is replaced.
var GetMixAddress = getMixAddressReal

// getMixAddress gets the address of the mix, which is the same as the MX record.
func getMixAddressReal(mixaddress string) (string, error) {
	rpchost := smtpclient.LookupMX(smtpclient.GetMailDomain(mixaddress))
	if rpchost == "" {
		return "", ErrNoHost
	}
	address := rpchost + ":" + RPCPort
	return address, nil
}

func getHTTPClient(cacert []byte) *http.Client {
	tr := &http.Transport{}
	if cacert != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
		tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(cacert)
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(DefaultTimeOut),
	}
	return client
}

// HTTPSGet executes a get call over HTTPs.
func HTTPSGet(getURL string, cacert []byte) ([]byte, error) {
	client := getHTTPClient(cacert)
	resp, err := client.Get(getURL)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return body, nil
}

// HTTPSPost executes a post call over HTTPs.
func HTTPSPost(postValues url.Values, postURL string, cacert []byte) ([]byte, error) {
	client := getHTTPClient(cacert)
	resp, err := client.PostForm(postURL, postValues)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return body, nil
}

// GetMixKeys gets the keys for the mix.
func GetMixKeys(mixaddress string, cacert []byte) (*mixaddr.AddressStatement, error) {
	address, err := GetMixAddress(mixaddress)
	if err != nil {
		return nil, err
	}
	body, err := HTTPSGet("https://"+address+"/keys", cacert)
	if err != nil {
		return nil, err
	}
	stmt := new(mixaddr.AddressStatement)
	err = json.Unmarshal(body, stmt)
	if err != nil {
		return nil, err
	}
	return stmt, nil
}

// RevokeMessage calls the revokation RPC to revoke a message, if possible.
func RevokeMessage(revokeID []byte, mixaddress string, cacert []byte) (bool, error) {
	address, err := GetMixAddress(mixaddress)
	if err != nil {
		return false, err
	}
	revokeIDH := hex.EncodeToString(revokeID)
	body, err := HTTPSGet("https://"+address+"/revoke?revokeid="+revokeIDH, cacert)
	if err != nil {
		return false, err
	}
	if len(body) > 7 {
		if string(body[0:7]) == "REVOKED" {
			return true, nil
		}
		if string(body[0:5]) == "ERROR" {
			return false, fmt.Errorf("%s", string(body))
		}
	}
	return false, ErrProto
}
