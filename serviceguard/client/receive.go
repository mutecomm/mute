package client

// ReceiveToken receives a token, verifies it, checks for ownership and usage,
// and adds it to the wallet if not known.
func (c *Client) ReceiveToken(usage string, inputToken []byte) error {
	tokenEntry, err := c.Verify(inputToken)
	if err != nil {
		return err
	}
	if tokenEntry.Usage != usage {
		c.LastError = ErrUsageToken
		return ErrFinal
	}
	pubkey, _ := splitKey(c.walletKey)
	if *tokenEntry.OwnerPubKey != *pubkey {
		c.LastError = ErrOwnerToken
		return ErrFinal
	}
	retToken, err := c.walletStore.GetToken(tokenEntry.Hash, -1)
	if err != nil || retToken == nil {
		c.walletStore.SetToken(*tokenEntry)
		return nil
	}
	c.LastError = ErrTokenKnown
	return ErrFinal
}
