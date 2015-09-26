// Package capabilities defines the capabilities of the Mute key server.
package capabilities

var (
	// DefaultMethods defines the implemented methods of the key server.
	DefaultMethods = []string{
		"KeyRepository.Capabilities",
		"KeyRepository.CreateUID",
		"KeyRepository.FetchUID",
		"KeyRepository.UpdateUID",
		"KeyHashchain.FetchHashChain",
		"KeyHashchain.FetchLastHashChain",
		"KeyHashchain.LookupUID",
		"KeyInitRepository.AddKeyInit",
		"KeyInitRepository.FetchKeyInit",
		"KeyInitRepository.FlushKeyInit",
	}
)

// The Capabilities of a Mute key server.
type Capabilities struct {
	METHODS               []string // methods implemented from specification
	DOMAINS               []string // domains served
	KEYREPOSITORYURIS     []string // Key repository URIs
	KEYINITREPOSITORYURIS []string // KeyInit repository URIs
	KEYHASHCHAINURIS      []string // Key Hashchain URIs
	// TODO: last Key Hashchain entry
	// LASTENTRY   string      // last Key Hashchain entry
	TKNPUBKEY string // public wallet key for key server payment tokens
	// TODO: can be more than one key?
	SIGPUBKEY string // public signature key(s) of keyserver
}
