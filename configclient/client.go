// Package configclient implements a configuration fetcher.
package configclient

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"time"

	"github.com/mutecomm/mute/configclient/cahash"
	"github.com/mutecomm/mute/configclient/roundrobin"
	"github.com/mutecomm/mute/configclient/sortedmap"
	"github.com/mutecomm/mute/util/times"
)

var (
	// ErrHashWrong is returned if the cacert could not be verified.
	ErrHashWrong = errors.New("configclient: CACert hash wrong")
	// ErrNoServers is returned if no valid servers were configured.
	ErrNoServers = errors.New("configclient: No available servers")
)

// MaxReadBody is the maximum size of the body that is transferred.
const MaxReadBody = 1048576

const skew = 82800

// Config contains configuration data for the config call, and it's result.
type Config struct {
	PublicKey    []byte            // Public key of configd. Decoded/binary
	URLList      string            // The list of the configd urls. "10,www.google.com:3912;20,8.8.8.8:80;10,irl.com:1020"
	CACert       []byte            // The current CACert, if any. Will always be set after config update
	Map          map[string]string // The configuration map. If set it will be overwritten
	LastSignDate uint64            // The last signdate, will be updated
	Timeout      int64             // Timeout, can be zero (will be set to 30)
	servers      []string          // list of servers generated from URLList
	curServer    int               // current server in servers list
}

// Update a configuration structure.
func (c *Config) Update() error {
	var err error
	var cert *sortedmap.SignedMap
	var myCAhash, certHashb []byte
	var hisHash string
	var ok bool

	if c.Timeout == 0 {
		c.Timeout = 30
	}
	ts := roundrobin.ParseServers(c.URLList)
	sort.Sort(ts)
	c.servers = ts.Order()
	if len(c.servers) < 1 {
		return ErrNoServers
	}
	if c.LastSignDate == 0 {
		c.LastSignDate = uint64(times.Now() - skew)
	}
GetConfigLoop:
	for ; c.curServer < len(c.servers); c.curServer++ {
		cert, err = getConfig(c.servers[c.curServer], c.PublicKey, c.LastSignDate, c.Timeout)
		if err == nil {
			break GetConfigLoop
		}
	}
	if err != nil {
		return err
	}
	// Change server ordering to make working and untested first
	c.servers = append(c.servers[c.curServer:], c.servers[:c.curServer]...)
	c.curServer = 0

	if hisHash, ok = cert.Config["CACertHash"]; !ok {
		c.Map = cert.Config
		c.LastSignDate = cert.SignDate
		return nil
	}
	if certHashb, err = hex.DecodeString(hisHash); err != nil {
		return err
	}
	if c.CACert != nil {
		if myCAhash, err = cahash.Hash(c.CACert); err != nil {
			return err
		}
	}
	if !bytes.Equal(myCAhash, certHashb) {
	CALoop:
		for ; c.curServer < len(c.servers); c.curServer++ {
			c.CACert, err = getCACert(c.servers[c.curServer], hisHash, c.Timeout)
			if err == nil {
				break CALoop
			}
		}
	}
	if err != nil {
		return err
	}
	c.Map = cert.Config
	c.LastSignDate = cert.SignDate
	return nil
}

func readBody(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	p, err := ioutil.ReadAll(&io.LimitedReader{R: rc, N: MaxReadBody})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func fixURL(URL string) string {
	if URL[len(URL)-1] == '/' {
		return URL
	}
	return URL + "/"
}

// getConfig reads the config from the server url configURL and verifies it
// with ed25519 publicKey. lastSignDate, if greater than zero, is taken into
// consideration. Timeout is in seconds. Configuration can be accessed via
// cert.Config (map[string]string).
func getConfig(configURL string, publicKey []byte, lastSignDate uint64, timeout int64) (cert *sortedmap.SignedMap, err error) {
	c := &http.Client{Timeout: time.Second * time.Duration(timeout)}
	resp, err := c.Get(fixURL(configURL) + "config")
	if err != nil {
		return nil, err
	}
	p, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	return sortedmap.Certify(lastSignDate, publicKey, p)
}

// getCACert returns the ca certificate (verified). certHash is from
// GetConfig().Config["CACertHash"]
func getCACert(configURL string, certHash string, timeout int64) ([]byte, error) {
	c := &http.Client{Timeout: time.Second * time.Duration(timeout)}
	resp, err := c.Get(fixURL(configURL) + "cacert")
	if err != nil {
		return nil, err
	}
	p, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	testHash, err := cahash.Hash(p)
	if err != nil {
		return nil, err
	}
	certHashb, err := hex.DecodeString(certHash)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(testHash, certHashb) {
		return nil, ErrHashWrong
	}
	return p, nil
}
