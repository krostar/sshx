package sshx

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewCertificateFromOpenSSHAuthorizedKeyBytes creates a certificate from an authorized ssh key formatted bytes.
func NewCertificateFromOpenSSHAuthorizedKeyBytes(raw []byte) (*Certificate, error) {
	cert, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ssh certificate from raw openssh certificate: %v", err)
	}

	if cert, ok := cert.(*ssh.Certificate); ok {
		return (*Certificate)(cert), nil
	}

	return nil, fmt.Errorf("parsed authorized key is not a certificate but %T", cert)
}

// NewCertificateFromOpenSSHAuthorizedKeyFile creates a certificate from an authorized ssh key formatted file.
func NewCertificateFromOpenSSHAuthorizedKeyFile(filePath string) (*Certificate, error) {
	rawFile, err := os.ReadFile(filePath) //nolint:gosec // G304 is a choice here
	if err != nil {
		return nil, fmt.Errorf("unable to read %q file: %w", filePath, err)
	}

	cert, err := NewCertificateFromOpenSSHAuthorizedKeyBytes(rawFile)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Certificate aliases ssh.Certificate to extend it.
type Certificate ssh.Certificate

// IsValid returns true if a certificate is valid.
func (c Certificate) IsValid() error {
	now := time.Now()

	if validAfter := time.Unix(int64(c.ValidAfter), 0); c.ValidAfter != 0 {
		if now.Before(validAfter) {
			return fmt.Errorf("certificate validity starts in %s", time.Until(validAfter))
		}
	}

	if validBefore := time.Unix(int64(c.ValidBefore), 0); c.ValidBefore != 0 {
		if now.After(validBefore) {
			return fmt.Errorf("certificate validity expired %s ago", time.Until(validBefore)*-1)
		}
	}

	return nil
}
