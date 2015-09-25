package configclient

import (
	"encoding/hex"
	"flag"
	"testing"
)

var pubkeyStr = "f6b5289bbe4bfc678b1f670b3b2a4bc837f052108092ca926d09f7afca9f485f"
var configURL = "127.0.0.1:3080"
var server bool

func init() {
	flag.BoolVar(&server, "server", false, "run server tests")
	flag.Parse()
}

func TestClient(t *testing.T) {
	if !server {
		t.Skip("skipping test in non-server mode.")
	}
	publicKey, _ := hex.DecodeString(pubkeyStr)
	sm, err := getConfig("http://"+configURL, publicKey, 0, 10)
	if err != nil {
		t.Fatalf("Client error (configd running???): %s", err)
	}
	if _, ok := sm.Config["CACertHash"]; !ok {
		t.Fatal("No CACert")
	}
	cacert, err := getCACert("http://"+configURL, sm.Config["CACertHash"], 10)
	if err != nil {
		t.Errorf("GetCACert: %s", err)
	}
	if len(cacert) < 150 {
		t.Error("CACert short")
	}
	_, err = getCACert(configURL, pubkeyStr, 10)
	if err == nil {
		t.Error("GetCACert must fail, wrong hash!")
	}
}

func TestUpdate(t *testing.T) {
	if !server {
		t.Skip("skipping test in non-server mode.")
	}
	publicKey, _ := hex.DecodeString(pubkeyStr)

	c := &Config{
		PublicKey:    publicKey,
		URLList:      "10," + configURL,
		CACert:       nil,
		Map:          nil,
		LastSignDate: 0,
		Timeout:      0,
	}
	err := c.Update()
	if err != nil {
		t.Fatalf("Update: %s", err)
	}
	if len(c.CACert) < 150 {
		t.Fatal("No cert fetched")
	}
	if len(c.Map["CACertHash"]) < 30 {
		t.Fatal("Map not set")
	}
}
