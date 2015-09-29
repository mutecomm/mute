// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cache caches the key server capabilities and clients used for
// mutecrypt's cryptengine.
package cache

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/mutecomm/mute/keyserver/capabilities"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/serviceguard/common/jsonclient"
	"github.com/mutecomm/mute/util"
)

// A Cache caches key server capabilities and clients used for mutecrypt's
// cryptengine.
type Cache struct {
	clients      map[string]*jsonclient.URLClient      // maps domain to JSON-RPC client
	capabilities map[string]*capabilities.Capabilities // maps domain to
}

// New returns a new cache.
func New() *Cache {
	return &Cache{
		clients:      make(map[string]*jsonclient.URLClient),
		capabilities: make(map[string]*capabilities.Capabilities),
	}
}

// newClient creats a new JSON-RPC client for the key server at domain on
// port. If altHost is defined, it is used as the alternate hostname for the
// given domain name. homedir is used to load key server certificates.
func newClient(domain, port, altHost, homedir string) (*jsonclient.URLClient, error) {
	// determine used host string
	var host string
	if altHost != "" {
		host = altHost
	} else {
		host = domain
	}
	// create client
	url := "https://" + host + port + "/"
	cert, err := ioutil.ReadFile(path.Join(homedir, "certs", domain))
	if err != nil {
		return nil, err
	}
	client, err := jsonclient.New(url, cert)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Set requests capabilities information from key server at the given domain
// and port and caches the used JSON-RPC client and the resulting
// capabilities. If altHost is defined, it is used as the alternate hostname
// for the given domain name. homedir is used to load key server certificates.
func (c *Cache) Set(domain, port, altHost, homedir string) error {
	// create new JSON-RPC client
	client, err := newClient(domain, port, altHost, homedir)
	if err != nil {
		return err
	}
	// request capabilities from key server
	reply, err := client.JSONRPCRequest("KeyRepository.Capabilities", nil)
	if err != nil {
		return err
	}
	rep, ok := reply["CAPABILITIES"].(map[string]interface{})
	if !ok {
		return log.Error("cryptengine: key server capabilities reply has the wrong type")
	}
	// marshal the unstructured capabilties reply into a JSON byte array
	jsn, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// unmarshal the JSON byte array back into a capabilities struct
	var caps capabilities.Capabilities
	if err := json.Unmarshal(jsn, &caps); err != nil {
		return err
	}
	// cache client and capabilities
	c.clients[domain] = client
	c.capabilities[domain] = &caps
	return nil
}

// Get returns the cached JSON-RPC client and capabilities for the given
// domain and makes sure that the requiredMethod is supported. If no client
// has been cached, the cache is filled using the Set method with the given
// domain, port, altHost, and homedir parameters.
func (c *Cache) Get(
	domain, port, altHost, homedir, requiredMethod string,
) (*jsonclient.URLClient, *capabilities.Capabilities, error) {
	// check/set cache
	caps := c.capabilities[domain]
	if caps == nil {
		if err := c.Set(domain, port, altHost, homedir); err != nil {
			return nil, nil, err
		}
	}
	caps = c.capabilities[domain]
	// check requiredMethod
	if !util.ContainsString(caps.METHODS, requiredMethod) {
		return nil, nil, log.Errorf("cache: key server %s does not support %s method", domain, requiredMethod)

	}
	// return client and capabilities from cache
	client := c.clients[domain]
	if client == nil {
		panic(log.Criticalf("cache: key server client for domain %s undefined", domain))
	}
	return client, caps, nil
}

// ShowCapabilities shows the cached capabilities of the key server at domain
// on stdout. If no capabilities have been cached, the cache is filled using
// the Set method with the given domain, port, altHost, and homedir
// parameters.
func (c *Cache) ShowCapabilities(domain, port, altHost, homedir string) error {
	// check/set cache
	caps := c.capabilities[domain]
	if caps == nil {
		if err := c.Set(domain, port, altHost, homedir); err != nil {
			return err
		}
	}
	caps = c.capabilities[domain]
	// pretty-print capabilities
	jsn, err := json.MarshalIndent(caps, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsn))
	return nil
}
