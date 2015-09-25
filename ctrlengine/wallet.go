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
	if err := printWalletKey(w, privkey); err != nil {
		return err
	}
	return nil
}
