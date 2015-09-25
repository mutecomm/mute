// Package def defines all default values used in Mute.
package def

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"path"

	"github.com/mutecomm/mute/configclient"
	"github.com/mutecomm/mute/log"
	mixclient "github.com/mutecomm/mute/mix/client"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/serviceguard/client/guardrpc"
	"github.com/mutecomm/mute/serviceguard/client/keylookup"
	"github.com/mutecomm/mute/serviceguard/client/walletrpc"

	"github.com/agl/ed25519"
)

// InitMute initializes Mute with the configuration from config.
func InitMute(config *configclient.Config) error {
	var ok bool
	mixclient.RPCPort, ok = config.Map["mixclient.RPCPort"]
	if !ok {
		return log.Error("config.Map[\"mixclient.RPCPort\"] undefined")
	}
	var mixAddress string
	mixAddress, ok = config.Map["mixclient.MixAddress"]
	if !ok {
		return log.Error("config.Map[\"mixclient.RPCPort\"] undefined")
	}
	mixclient.GetMixAddress = func(string) (string, error) {
		return mixAddress, nil
	}
	walletrpc.ServiceURL, ok = config.Map["walletrpc.ServiceURL"]
	if !ok {
		return log.Error("config.Map[\"walletrpc.ServiceURL\"] undefined")
	}
	keylookup.ServiceURL, ok = config.Map["keylookup.ServiceURL"]
	if !ok {
		return log.Error("config.Map[\"keylookup.ServiceURL\"] undefined")
	}
	guardrpc.ServiceURL, ok = config.Map["guardrpc.ServiceURL"]
	if !ok {
		return log.Error("config.Map[\"guardrpc.ServiceURL\"] undefined")
	}
	var trustRoot string
	trustRoot, ok = config.Map["serviceguard.TrustRoot"]
	if !ok {
		return log.Error("config.Map[\"serviceguard.TrustRoot\"] undefined")
	}
	var err error
	client.TrustRoot, err = decodeED25519PubKey(trustRoot)
	if err != nil {
		return err
	}
	// set CA cert
	CACert = config.CACert

	// muteaccd owner
	var owner string
	owner, ok = config.Map["muteaccd.owner"]
	if !ok {
		return log.Error("config.Map[\"muteaccd.owner\"] undefined")
	}
	AccdOwner, err = decodeED25519PubKey(owner)
	if err != nil {
		return err
	}

	// muteaccd usage
	AccdUsage, ok = config.Map["muteaccd.usage"]
	if !ok {
		return log.Error("config.Map[\"muteaccd.usage\"] undefined")
	}

	return nil
}

// InitMuteFromFile initializes Mute with the config file from
// homedir/config/mute.berlin.
func InitMuteFromFile(homedir string) error {
	configdir := path.Join(homedir, "config")
	jsn, err := ioutil.ReadFile(path.Join(configdir, DefaultDomain))
	if err != nil {
		return log.Error(err)
	}
	var config configclient.Config
	if err := json.Unmarshal(jsn, &config); err != nil {
		return err
	}
	return InitMute(&config)
}

const (
	// Version is the current Mute version.
	// We use semantic versioning (http://semver.org/).
	Version = "0.1.0"

	// DefaultDomain defines the default domain for Mute.
	DefaultDomain = "mute.berlin"
	// PubkeyStr is the hex-encoded public key of the configuration server
	// (testnet).
	PubkeyStr = "f6b5289bbe4bfc678b1f670b3b2a4bc837f052108092ca926d09f7afca9f485f"
	// ConfigURL defines the URL of the  of the configuration server (testnet).
	ConfigURL = "127.0.0.1:3080"

	// KDFIterationsDB defines the default number of KDF iterations for the
	// message and key database.
	KDFIterationsDB = 64000

	// HashChainChannelSize defines the default buffer size for the hash chain
	// input channel.
	HashChainChannelSize = 1000
	// KeyStoreChannelSize defines the default buffer size for the key store
	// input channel.
	KeyStoreChannelSize = 1000
	// KeyInitStoreChannelSize defines the default buffer size for the key init
	// store input channel.
	KeyInitStoreChannelSize = 1000
	// MessagePoolChannelSize defines the default buffer size for the message
	// pool input channel.
	MessagePoolChannelSize = 1000

	// Hostmutekeyd defines the default host for mutekeyd.
	Hostmutekeyd = "mute.berlin"
	// Hostmutemixd defines the default host for mutemixd.
	Hostmutemixd = "mute.berlin"
	// Hostmuteaccd defines the default host for muteaccd.
	Hostmuteaccd = "mute.berlin"

	// Portmutekeyd defines the default port for mutekeyd.
	Portmutekeyd = ":3000"
	// Portmutemixd defines the default port for mutemixd.
	Portmutemixd = ":3001"
	// Portmuteaccd defines the default port for muteaccd.
	Portmuteaccd = ":3002"

	// MinDelay defines the default minimum delay setting for messages to mix.
	MinDelay = int32(120)

	// MaxDelay defines the default maximum delay setting for messages to mix.
	MaxDelay = int32(300)

	// MinMinDelay defines the minimum minimum delay setting for messages to
	// mix.
	MinMinDelay = 1

	// MinMaxDelay defines the minimum maximum delay setting for messages to
	// mix.
	MinMaxDelay = 2
)

// CACert is the default certificate authority used for Mute.
var CACert []byte

// AccdOwner is the wallet owner public key of the Mute account daemon.
var AccdOwner *[ed25519.PublicKeySize]byte

// AccdUsage is the wallet usage for the Mute account daemon.
var AccdUsage string

// TODO: extract method
func decodeED25519PubKey(p string) (*[ed25519.PublicKeySize]byte, error) {
	ret := new([ed25519.PublicKeySize]byte)
	pd, err := hex.DecodeString(p)
	if err != nil {
		return nil, err
	}
	copy(ret[:], pd)
	return ret, nil
}
