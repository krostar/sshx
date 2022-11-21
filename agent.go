package sshx

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrSignerNotFound is return when the signer is expected to exist but does not.
const ErrSignerNotFound sentinelError = "signer not found"

// Agent contains all kind of methods to manipulate ssh agent.
type Agent struct{ agent.Agent }

var _sshAuthSockFileEnv = "SSH_AUTH_SOCK" //nolint:gochecknoglobals // required for testing purposes

// NewAgent creates a new ssh agent from the unix socket contained in the SSH_AUTH_SOCK environment variable.
func NewAgent() (*Agent, func() error, error) {
	agentUnixSocket, isset := os.LookupEnv(_sshAuthSockFileEnv)
	if !isset {
		return nil, nil, fmt.Errorf("undefined agent unix socket env %q", _sshAuthSockFileEnv)
	}

	agentConn, err := net.Dial("unix", agentUnixSocket)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to connect to the agent: %w", err)
	}

	return &Agent{Agent: agent.NewClient(agentConn)}, agentConn.Close, nil
}

// UpsertKey replaces the provided private key in the agent (remove if exists in the agent then insert it).
func (a *Agent) UpsertKey(privateKey PrivateKey) error {
	if err := a.RemoveMatchingPublicKey(privateKey.PublicKey()); err != nil {
		return fmt.Errorf("unable to remove existing private key from agent: %v", err)
	}

	if err := a.Add(agent.AddedKey{PrivateKey: privateKey.Raw()}); err != nil {
		return fmt.Errorf("unable to add private key to agent: %v", err)
	}

	return nil
}

// UpsertCertificate replaces the provided private key and cert from the agent, if the provided cert is valid.
func (a *Agent) UpsertCertificate(privateKey PrivateKey, cert Certificate) error {
	if err := cert.IsValid(); err != nil {
		return fmt.Errorf("invalid certificate: %v", err)
	}

	if err := a.UpsertKey(privateKey); err != nil {
		return fmt.Errorf("unable to upsert private key: %v", err)
	}

	var lifetimeSecs uint32
	if validBefore := time.Unix(int64(cert.ValidBefore), 0); cert.ValidBefore != 0 {
		lifetimeSecs = uint32(time.Until(validBefore).Seconds())
	}

	if err := a.Add(agent.AddedKey{
		PrivateKey:   privateKey.Raw(),
		Certificate:  (*ssh.Certificate)(&cert),
		LifetimeSecs: lifetimeSecs,
	}); err != nil {
		return fmt.Errorf("unable to add certificate to agent: %v", err)
	}

	return nil
}

// GetSignerMatchingPublicKey returns a signer from the agent matching the provided public key.
func (a *Agent) GetSignerMatchingPublicKey(pubKey PublicKey) (ssh.Signer, error) {
	agentSigners, err := a.Signers()
	if err != nil {
		return nil, fmt.Errorf("unable to get signers in agent: %v", err)
	}

	publicKeyWire := pubKey.Marshal()
	for _, signer := range agentSigners {
		if bytes.Equal(publicKeyWire, signer.PublicKey().Marshal()) {
			return signer, nil
		}
	}

	return nil, fmt.Errorf("%w", ErrSignerNotFound)
}

// RemoveMatchingPublicKey removes all keys matching the provided public key.
func (a *Agent) RemoveMatchingPublicKey(pubKey PublicKey) error {
	rawPubKey := pubKey.Marshal()

	keys, err := a.List()
	if err != nil {
		return fmt.Errorf("unable to list keys in agent: %v", err)
	}

	for _, key := range keys {
		if bytes.Equal(rawPubKey, key.Marshal()) {
			if err := a.Remove(key); err != nil {
				return fmt.Errorf("unable to remove key from agent: %v", err)
			}
		}
	}

	return nil
}
