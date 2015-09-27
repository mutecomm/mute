// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptengine

import (
	"fmt"
	"strings"
)

func (ce *CryptEngine) getCapabilities(domainAndPort, altHost string) error {
	if altHost == "" && ce.keydHost != "" {
		altHost = ce.keydHost
	}
	var domain string
	var port string
	parts := strings.Split(domainAndPort, ":")
	switch len(parts) {
	case 1:
		domain = parts[0]
		port = ce.keydPort
	case 2:
		domain = parts[0]
		port = ":" + parts[1]
	default:
		return fmt.Errorf("cryptengine: cannot parse DMN[:PRT] argument: %s", domainAndPort)
	}
	return ce.cache.Set(domain, port, altHost, ce.homedir)
}

func (ce *CryptEngine) showCapabilities(domain, altHost string) error {
	if altHost == "" && ce.keydHost != "" {
		altHost = ce.keydHost
	}
	return ce.cache.ShowCapabilities(domain, ce.keydPort, altHost, ce.homedir)
}
