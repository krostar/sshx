package sshx

import (
	"crypto"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// PublicKey defines common methods for all ssh public keys.
type PublicKey interface {
	ssh.PublicKey

	Raw() crypto.PublicKey
	Equal(PublicKey) error
	String() string
}

// WrapSSHPublicKey wraps the provided ssh.PublicKey.
func WrapSSHPublicKey(sshPublicKey ssh.PublicKey) PublicKey {
	switch t := sshPublicKey.(type) {
	case PublicKey:
		return t
	default:
		return &publicKey{PublicKey: sshPublicKey}
	}
}

// NewPublicKeyFromOpenSSHAuthorizedKeyBytes parses an SSH public key from PEM bytes.
func NewPublicKeyFromOpenSSHAuthorizedKeyBytes(raw []byte) (PublicKey, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ssh public key from raw openssh public key: %v", err)
	}
	return WrapSSHPublicKey(sshPubKey), nil
}

// NewPublicKeyFromOpenSSHAuthorizedKeyFile parses an SSH public key from PEM file.
func NewPublicKeyFromOpenSSHAuthorizedKeyFile(filePath string) (PublicKey, error) {
	rawFileContent, err := os.ReadFile(filePath) //nolint:gosec // G304 is a choice here
	if err != nil {
		return nil, fmt.Errorf("unable to read %q file: %w", filePath, err)
	}
	return NewPublicKeyFromOpenSSHAuthorizedKeyBytes(rawFileContent)
}

type publicKey struct {
	ssh.PublicKey
}

func (key publicKey) Raw() crypto.PublicKey {
	cryptoPubKeyGetter, ok := key.PublicKey.(ssh.CryptoPublicKey)
	if !ok {
		panic(fmt.Sprintf("ssh public key %T does not implement crypto public key", key.PublicKey))
	}
	return cryptoPubKeyGetter.CryptoPublicKey()
}

func (key publicKey) Equal(comparedKey PublicKey) error {
	comparedKeyCryptoPubKey := comparedKey.Raw()
	cryptoPubKey := key.Raw()

	cryptoPubKeyWithEqual, ok := cryptoPubKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		return fmt.Errorf("crypto public key %T does not implement Equal method", cryptoPubKey)
	}

	if !cryptoPubKeyWithEqual.Equal(comparedKeyCryptoPubKey) {
		return fmt.Errorf("crypto public key %T is not equal to provided crypto public key %T", cryptoPubKeyWithEqual, comparedKey)
	}

	return nil
}

func (key publicKey) String() string {
	return string(ssh.MarshalAuthorizedKey(key.PublicKey))
}
