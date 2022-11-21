package sshx

import (
	"context"
	"fmt"
	"time"
)

func (c *Client) CheckLivenessUntilNotAlive(ctx context.Context, aliveCheckInterval time.Duration, notAliveCountExit uint) error {
	ticker := time.NewTicker(aliveCheckInterval)
	defer ticker.Stop()

	var (
		notAliveCount uint
		lastError     error
	)

	for {
		if notAliveCount >= notAliveCountExit {
			return fmt.Errorf("%s liveness check failed %d time consecutively (last error: %v)", c.addr, notAliveCount, lastError)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.IsAlive(); err != nil {
				notAliveCount++
				lastError = err
			} else {
				notAliveCount = 0
			}

			ticker.Reset(aliveCheckInterval)
		}
	}
}

func (c *Client) IsAlive() error {
	if _, _, err := c.Client.SendRequest("keepalive@golang.org", true, nil); err != nil {
		return fmt.Errorf("unable to send keepalive request: %w", err)
	}
	return nil
}
