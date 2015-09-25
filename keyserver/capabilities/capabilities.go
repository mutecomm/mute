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
	METHODS               []string
	DOMAINS               []string
	KEYREPOSITORYURIS     []string
	KEYINITREPOSITORYURIS []string
	KEYHASHCHAINURIS      []string
	// TODO: last Key Hashchain entry
	TKNPUBKEY string // public key for key server payment tokens
	SIGPUBKEY string // TODO: can be more than one key?
}
