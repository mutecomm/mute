package client

import (
	"runtime"
	"time"
)

// Runner:
// - Check for unfinished reissues
// - Run expire
// - Fill targets

// Runner starts the background runner for token-store management.
func (c *Client) Runner() {
	go c.runner()
}

// StopRunner stops the runner. Should be called non-blocking (go StopRunner()).
func (c *Client) StopRunner() {
	c.stopChan <- true
}

func (c *Client) runner() {
	// Prevent double-start
	runnerLock.Lock()
	if c.runnerRunning {
		return
	}
	c.runnerRunning = true
	runnerLock.Unlock()
	for {
		var actionCount int
		if len(c.stopChan) > 0 {
			<-c.stopChan
			runtime.Goexit()
		}
		onlineGroup.Add(1)
		// Delete some expired tokens
		if c.walletStore.ExpireUnusable() {
			actionCount++
		}
		// Finish expired reissues
		reissueTokenHash := c.walletStore.GetInReissue()
		if reissueTokenHash != nil {
			c.ReissueToken(reissueTokenHash, nil) // Continue reissue on token
			actionCount++
		}
		// Update an expiring token
		reissueTokenHash = c.walletStore.GetExpire()
		if reissueTokenHash != nil {
			tokenData, err := c.walletStore.GetToken(reissueTokenHash, -1)
			if err == nil {
				c.ReissueToken(tokenData.Hash, nil) // Reissue token to new target
				actionCount++
			}
		}
		// Meet targets
		if c.meetTarget() {
			actionCount++
		}
		onlineGroup.Done()
		if actionCount == 0 {
			time.Sleep(time.Second * 3)
		}
	}
}

// meetTarget tries to meet min-fill targets on the client.
// It returns true if had to take action.
func (c *Client) meetTarget() bool {
	runnerLock.Lock()
	defer runnerLock.Unlock()
	if c.target == nil {
		return false
	}
LoadLoop:
	for owner, target := range c.target {
		balance := c.GetBalance(target.Usage, &owner)
		if balance >= target.LowWaterMark && target.balance <= 0 {
			// We still have enough tokens and we arent loading
			continue LoadLoop
		}
		if balance >= target.HighWaterMark {
			// We have enough tokens now, stop loading
			target.balance = 0
			c.target[owner] = target
			continue LoadLoop
		} else {
			// We need to load. Either we are below LowWaterMark or we are in loading already
			target.balance = target.HighWaterMark - balance
			c.target[owner] = target
		}
		// We only go one step
		_, err := c.WalletToken(target.Usage, &owner)
		if err == nil { // Errors should be recoverd by  c.walletStore.GetInReissue(), c.ReissueToken
			target.balance--
			c.target[owner] = target
		}
		// Never care about more than one owner
		return true
	}
	return false
}
