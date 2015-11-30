// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"time"

	"github.com/agl/ed25519"
	"github.com/jpillora/backoff"
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/serviceguard/client"
)

// WalletGetTokenMaxDuration defines the maximum duration before the
// acquisition of a token from the wallet is aborted.
var WalletGetTokenMaxDuration = 5 * time.Minute // 5m

// WalletGetToken returns a token for the given usage and owner from
// walletClient. It automatically retries if it gets a client.ErrRetry error.
func WalletGetToken(
	walletClient *client.Client,
	usage string,
	owner *[ed25519.PublicKeySize]byte,
) (*client.TokenEntry, error) {
	token, err := walletClient.GetToken(usage, owner)
	if err == client.ErrRetry {
		log.Warnf("WalletGetToken(): ErrRetry: %s", walletClient.LastError)
		b := &backoff.Backoff{
			Min:    100 * time.Millisecond,
			Max:    5 * time.Second,
			Factor: 1.5,
			Jitter: false,
		}
		var total time.Duration
		for {
			d := b.Duration()
			time.Sleep(d)
			total += d
			token, err = walletClient.GetToken(usage, owner)
			if err != client.ErrRetry {
				break
			}
			if total >= WalletGetTokenMaxDuration {
				// total duration is larger than max duration -> stop trying
				break
			}
			log.Warnf("WalletGetToken(): ErrRetry: %s", walletClient.LastError)
		}
	}
	if err != nil {
		return nil, log.Error(walletClient.LastError)
	}
	return token, nil
}
