// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cahash verifies a pem-encoded certificate and returns the hash
package cahash

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
)

// Hash returns the hash of cert, or error if cert is not a valid pem-encoded x509 cert
func Hash(cert []byte) ([]byte, error) {
	block, _ := pem.Decode(cert)
	_, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, err
	}
	x := sha512.Sum512(block.Bytes)
	return x[:], nil
}
