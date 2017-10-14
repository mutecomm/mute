// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"fmt"
	"io"

	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/msgdb"
)

func printWalletKey(w io.Writer, privkey string) error {
	pk, err := base64.Decode(privkey)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "WALLETPUBKEY:\t%s\n", base64.Encode(pk[32:]))
	return nil
}

func (ce *CtrlEngine) walletPubkey(w io.Writer) error {
	privkey, err := ce.msgDB.GetValue(msgdb.WalletKey)
	if err != nil {
		return err
	}
	return printWalletKey(w, privkey)
}

func (ce *CtrlEngine) walletBalance(w io.Writer) error {
	msgSelf := ce.client.GetBalanceOwn("Message")
	msgNonSelf := ce.client.GetBalance("Message", nil)
	uidSelf := ce.client.GetBalanceOwn("UID")
	uidNonSelf := ce.client.GetBalance("UID", nil)
	accSelf := ce.client.GetBalanceOwn("Account")
	accNonSelf := ce.client.GetBalance("Account", nil)
	fmt.Fprintf(w, "Message: self:%8d; non-self:%8d; total=%8d\n", msgSelf, msgNonSelf, msgSelf+msgNonSelf)
	fmt.Fprintf(w, "UID:     self:%8d; non-self:%8d; total=%8d\n", uidSelf, uidNonSelf, uidSelf+uidNonSelf)
	fmt.Fprintf(w, "Account: self:%8d; non-self:%8d; total=%8d\n", accSelf, accNonSelf, accSelf+accNonSelf)
	return nil
}
