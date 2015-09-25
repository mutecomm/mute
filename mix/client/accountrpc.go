package client

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/mutecomm/mute/serviceguard/common/walletauth"
	"github.com/mutecomm/mute/util/times"

	"github.com/agl/ed25519"
)

func splitKey(privkey *[ed25519.PrivateKeySize]byte) (pubkey *[ed25519.PublicKeySize]byte) {
	pubkey = new([ed25519.PublicKeySize]byte)
	copy(pubkey[:], privkey[ed25519.PrivateKeySize-ed25519.PublicKeySize:])
	return pubkey
}

// PayAccount makes a pay call to server (or selects a new one) to create or
// extend an account identified by privkey.
func PayAccount(privkey *[ed25519.PrivateKeySize]byte, paytoken []byte, serverKnown string, cacert []byte) (server string, err error) {
	var authtoken []byte
	lastcounter := uint64(times.NowNano())
	pubkey := splitKey(privkey)
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		if authtoken == nil {
			authtoken = walletauth.CreateToken(pubkey, privkey, lastcounter+1)
		}
		server, lastcounter, err = payAccount(authtoken, paytoken, serverKnown, cacert)
		if err == walletauth.ErrReplay {
			authtoken = nil
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		break CallLoop
	}
	return server, err
}

func payAccount(authtoken, paytoken []byte, serverKnown string, cacert []byte) (server string, lastcounter uint64, err error) {
	var ServerT string
	var ok bool
	method := "AccountServer.LoadAccount"
	url := DefaultAccountServer
	if server != "" {
		url = server
	}
	url = "https://" + url + ":" + RPCPort + "/account"
	client, err := DefaultClientFactory(url, cacert)
	if err != nil {
		return "", 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	paytokenEnc := base64.StdEncoding.EncodeToString(paytoken)
	data, err := client.JSONRPCRequest(method, struct {
		AuthToken string
		PayToken  string
	}{
		AuthToken: authtokenEnc,
		PayToken:  paytokenEnc,
	})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return "", LastCounter, err
	}
	if _, ok = data["Server"]; !ok {
		return "", 0, ErrProto
	}
	if ServerT, ok = data["Server"].(string); !ok {
		return "", 0, ErrProto
	}
	return ServerT, 0, nil
}

// DeleteAccount deletes the account of privkey on server.
func DeleteAccount(privkey *[ed25519.PrivateKeySize]byte, server string, cacert []byte) (err error) {
	var authtoken []byte
	var result bool
	lastcounter := uint64(times.NowNano())
	pubkey := splitKey(privkey)
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		if authtoken == nil {
			authtoken = walletauth.CreateToken(pubkey, privkey, lastcounter+1)
		}
		result, lastcounter, err = delAccount(authtoken, server, cacert)
		if err == walletauth.ErrReplay {
			authtoken = nil
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		break CallLoop
	}
	if err != nil {
		return err
	}
	if result {
		return nil
	}
	return ErrNoMatch
}

// delAccount delets an account
func delAccount(authtoken []byte, server string, cacert []byte) (bool, uint64, error) {
	var ok, ResultT bool
	method := "AccountServer.DeleteAccount"
	url := "https://" + server + ":" + RPCPort + "/account"
	client, err := DefaultClientFactory(url, cacert)
	if err != nil {
		return false, 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	data, err := client.JSONRPCRequest(method, struct{ AuthToken string }{AuthToken: authtokenEnc})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return false, LastCounter, err
	}
	if _, ok = data["Result"]; !ok {
		return false, 0, ErrProto
	}
	if ResultT, ok = data["Result"].(bool); !ok {
		return false, 0, ErrProto
	}
	return ResultT, 0, nil
}

// AccountStat gets the time until which the account of privkey on server
// expires.
func AccountStat(privkey *[ed25519.PrivateKeySize]byte, server string, cacert []byte) (loadTime int64, err error) {
	var authtoken []byte
	lastcounter := uint64(times.NowNano())
	pubkey := splitKey(privkey)
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		if authtoken == nil {
			authtoken = walletauth.CreateToken(pubkey, privkey, lastcounter+1)
		}
		loadTime, lastcounter, err = accountStat(authtoken, server, cacert)
		if err == walletauth.ErrReplay {
			authtoken = nil
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		break CallLoop
	}
	if err != nil {
		return 0, err
	}
	return loadTime, nil
}

// accountStat real call
func accountStat(authtoken []byte, server string, cacert []byte) (int64, uint64, error) {
	var ok bool
	var LoadTimeT float64
	method := "AccountServer.AccountStat"
	url := "https://" + server + ":" + RPCPort + "/account"
	client, err := DefaultClientFactory(url, cacert)
	if err != nil {
		return 0, 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	data, err := client.JSONRPCRequest(method, struct{ AuthToken string }{AuthToken: authtokenEnc})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return 0, LastCounter, err
	}
	if _, ok = data["LoadTime"]; !ok {
		return 0, 0, ErrProto
	}
	if LoadTimeT, ok = data["LoadTime"].(float64); !ok {
		return 0, 0, ErrProto
	}
	return int64(LoadTimeT), 0, nil
}

// MessageMeta contains metadata on a message.
type MessageMeta struct {
	MessageID                              []byte
	ReceiveTime, ReceiveTimeNano, ReadTime int64
	UserKey                                [ed25519.PublicKeySize]byte
}

// ListMessages gets the messages for account identified by privkey.
func ListMessages(privkey *[ed25519.PrivateKeySize]byte, lastMessageTime int64, server string, cacert []byte) (messages []MessageMeta, err error) {
	var authtoken []byte
	lastcounter := uint64(times.NowNano())
	pubkey := splitKey(privkey)
	i := 3 // This should skip error and a collision, but stop if it's an ongoing parallel access
CallLoop:
	for {
		if authtoken == nil {
			authtoken = walletauth.CreateToken(pubkey, privkey, lastcounter+1)
		}
		messages, lastcounter, err = listMessages(authtoken, lastMessageTime, server, cacert)
		if err == walletauth.ErrReplay {
			authtoken = nil
			if i > 0 {
				i--
				continue CallLoop
			}
		}
		break CallLoop
	}
	if err != nil {
		return nil, err
	}
	return messages, nil
}

// listMessages real call
func listMessages(authtoken []byte, lastMessageTime int64, server string, cacert []byte) ([]MessageMeta, uint64, error) {
	var ok bool
	var messages []MessageMeta
	method := "AccountServer.ListMessages"
	url := "https://" + server + ":" + RPCPort + "/account"
	client, err := DefaultClientFactory(url, cacert)
	if err != nil {
		return nil, 0, err
	}
	authtokenEnc := base64.StdEncoding.EncodeToString(authtoken)
	data, err := client.JSONRPCRequest(method, struct {
		AuthToken       string
		LastReceiveTime int64
	}{
		AuthToken:       authtokenEnc,
		LastReceiveTime: lastMessageTime,
	})
	if err != nil {
		LastCounter, err := walletauth.IsReplay(err)
		return nil, LastCounter, err
	}
	if _, ok = data["Messages"]; !ok {
		return nil, 0, ErrProto
	}
	messagesI, ok := data["Messages"].([]interface{})
	if !ok {
		return nil, 0, ErrProto
	}
	if len(messagesI) > 0 {
		for _, e := range messagesI {
			x := e.(map[string]interface{})

			ReceiveTime, ok := x["ReceiveTime"].(float64)
			if !ok {
				err = ErrProto
				break
			}
			ReceiveTimeNano, ok := x["ReceiveTimeNano"].(float64)
			if !ok {
				err = ErrProto
				break
			}
			ReadTime, ok := x["ReadTime"].(float64)
			if !ok {
				err = ErrProto
				break
			}
			uks, ok := x["UserKey"].(string)
			if !ok {
				err = ErrProto
				break
			}
			uk, err := hex.DecodeString(uks)
			if err != nil {
				break
			}
			ukh := new([ed25519.PublicKeySize]byte)
			copy(ukh[:], uk)

			mis, ok := x["MessageID"].(string)
			if !ok {
				err = ErrProto
				break
			}
			mi, err := hex.DecodeString(mis)
			if err != nil {
				break
			}
			messages = append(messages, MessageMeta{
				MessageID:       mi,
				ReceiveTime:     int64(ReceiveTime),
				ReceiveTimeNano: int64(ReceiveTimeNano),
				ReadTime:        int64(ReadTime),
				UserKey:         *ukh,
			})
		}
		if err != nil {
			return nil, 0, err
		}
	}
	return messages, 0, nil
}
