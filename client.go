package sshx

import (
	"fmt"
	"net"

	"go.uber.org/multierr"
	"golang.org/x/crypto/ssh"
)

// Client wraps ssh.Client handle liveness and bridges.
type Client struct {
	*ssh.Client
	addr   string
	bridge *Client
}

// NewClient returns a new Client.
func NewClient(cfg *ClientConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid ssh config: %v", err)
	}

	if cfg.Bridge == nil {
		conn, err := net.DialTimeout("tcp", cfg.Addr, cfg.SSHClientConfig.Timeout)
		if err != nil {
			return nil, fmt.Errorf("unable to dial %s: %v", cfg.Addr, err)
		}
		conn = &clientTCPConnWithSoftDeadline{Conn: conn, timeout: cfg.SSHClientConfig.Timeout}

		sshConn, sshChan, sshReq, err := ssh.NewClientConn(conn, cfg.Addr, &cfg.SSHClientConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to create client conn: %v", err)
		}

		return &Client{
			Client: ssh.NewClient(sshConn, sshChan, sshReq),
			addr:   cfg.Addr,
		}, nil
	}

	bridgedClient, err := NewClient(cfg.Bridge)
	if err != nil {
		return nil, fmt.Errorf("unable to create bridge %s client for %s: %v", cfg.Bridge.Addr, cfg.Addr, err)
	}

	bridgedConn, err := bridgedClient.Dial("tcp", cfg.Addr)
	if err != nil {
		err = multierr.Append(err, bridgedClient.Close())
		return nil, fmt.Errorf("unable to dial %s through bridge %s: %v", cfg.Addr, bridgedClient.addr, err)
	}
	bridgedConn = &clientTCPConnWithHardDeadline{Conn: bridgedConn, timeout: cfg.SSHClientConfig.Timeout}

	sshBridgedConn, sshBridgedChan, sshBridgedReq, err := ssh.NewClientConn(bridgedConn, cfg.Addr, &cfg.SSHClientConfig)
	if err != nil {
		err = multierr.Append(err, bridgedClient.Close())
		return nil, fmt.Errorf("unable to create client %s conn through bridge %s: %v", cfg.Addr, bridgedClient.addr, err)
	}

	return &Client{
		Client: ssh.NewClient(sshBridgedConn, sshBridgedChan, sshBridgedReq),
		addr:   cfg.Addr,
		bridge: bridgedClient,
	}, nil
}

// Close closes the underlying client and all bridges.
func (c *Client) Close() error {
	var err error

	if closeErr := c.Client.Close(); closeErr != nil {
		err = fmt.Errorf("unable to close %s conn: %v", c.addr, closeErr)
	}

	if c.bridge != nil {
		if bridgeCloseErr := c.bridge.Close(); bridgeCloseErr != nil {
			bridgeCloseErr = fmt.Errorf("unable to close %s's bridge %s conn: %v", c.addr, c.bridge.addr, bridgeCloseErr)
			err = fmt.Errorf("%v, %s", err, bridgeCloseErr)
		}
	}

	return err
}
