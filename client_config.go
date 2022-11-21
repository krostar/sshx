package sshx

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ClientConfig stores the ssh configuration.
type ClientConfig struct {
	Addr            string
	SSHClientConfig ssh.ClientConfig
	Bridge          *ClientConfig
}

// Validate returns whenever the configuration is valid.
func (cfg *ClientConfig) Validate() error {
	if cfg.Addr == "" {
		return errors.New("empty addr")
	}

	if cfg.SSHClientConfig.Timeout == 0 {
		return errors.New("empty network timeout")
	}

	if cfg.Bridge != nil {
		if err := cfg.Bridge.Validate(); err != nil {
			return fmt.Errorf("bridge of %s config is invalid: %v", cfg.Addr, err)
		}
	}

	return nil
}
