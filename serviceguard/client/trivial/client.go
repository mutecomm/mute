// Package trivial implements a trivial wrapper for mute/serviceguard/client
package trivial

import (
	"github.com/agl/ed25519"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/serviceguard/client/walletstore"
	"github.com/mutecomm/mute/serviceguard/common/types"
)

// New takes a database handler or URL and creates the key backend and the
// walletstore from it. walletKey is the private key for the client wallet.
// cacert is the SSLCACert of the server.
func New(database interface{}, walletKey *[ed25519.PrivateKeySize]byte, cacert []byte) (*client.Client, error) {
	keyBackends := make([]types.Backend, 0, 1)
	keyBackends = append(keyBackends, types.Backend{Type: "database", Value: database})
	walletStore, err := walletstore.New(database)
	if err != nil {
		return nil, err
	}
	return client.New(keyBackends, walletStore, walletKey, cacert)
}
