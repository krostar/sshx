package sshx

import (
	"crypto"
	"crypto/dsa"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type PrivateKey interface {
	Signer() ssh.Signer
	PublicKey() PublicKey

	Raw() crypto.PrivateKey
	Equal(PrivateKey) error
}

func WrapPrivateKey(cryptoPrivKey crypto.PrivateKey) (PrivateKey, error) {
	var pubKey PublicKey
	{ // handle keys not implementing Public() interface{}.
		var cryptoPubKey crypto.PublicKey

		if cryptoPrivKeyWithPublicKeyGetter, ok := cryptoPrivKey.(interface{ Public() crypto.PublicKey }); ok {
			cryptoPubKey = cryptoPrivKeyWithPublicKeyGetter.Public()
		} else {
			switch typ := cryptoPrivKey.(type) {
			case *dsa.PrivateKey:
				cryptoPubKey = &typ.PublicKey
			default:
				// we don't know how to get the public key, either ssh.NewPublicKey know, or it won't work
				cryptoPubKey = cryptoPrivKey
			}
		}

		sshPubKey, err := ssh.NewPublicKey(cryptoPubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ssh public key: %v", err)
		}

		pubKey = WrapSSHPublicKey(sshPubKey)
	}

	signer, err := ssh.NewSignerFromKey(cryptoPrivKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create signer from key %v", err)
	}

	return &privateKey{
		privateKey: cryptoPrivKey,
		publicKey:  pubKey,
		signer:     signer,
	}, nil
}

func NewPrivateKeyFromPEMBytes(raw []byte, passphraseGetter func() ([]byte, error)) (PrivateKey, error) {
	switch privKey, err := ssh.ParseRawPrivateKey(raw); {
	case err == nil:
		return WrapPrivateKey(privKey)
	case err != nil:
		if passphraseError := new(ssh.PassphraseMissingError); !(errors.As(err, &passphraseError) && passphraseGetter != nil) {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}
	}

	passphrase, err := passphraseGetter()
	if err != nil {
		return nil, fmt.Errorf("unable to get passphrase: %w", err)
	}

	privKey, err := ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key with passphrase: %v", err)
	}

	return WrapPrivateKey(privKey)
}

func NewPrivateKeyFromPEMFile(filePath string, passphraseGetter func() ([]byte, error)) (PrivateKey, error) {
	rawFileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read %q file: %w", filePath, err)
	}
	return NewPrivateKeyFromPEMBytes(rawFileContent, passphraseGetter)
}

type privateKey struct {
	privateKey crypto.PrivateKey
	publicKey  PublicKey
	signer     ssh.Signer
}

func (key privateKey) Signer() ssh.Signer     { return key.signer }
func (key privateKey) Raw() crypto.PrivateKey { return key.privateKey }
func (key privateKey) PublicKey() PublicKey   { return key.publicKey }

func (key privateKey) Equal(comparedKey PrivateKey) error {
	compareKeyCryptoPrivKey := comparedKey.Raw()
	cryptoPrivKey := key.Raw()

	cryptoPrivKeyWithEqual, ok := cryptoPrivKey.(interface {
		Equal(crypto.PrivateKey) bool
	})
	if !ok {
		return fmt.Errorf("crypto private key %T does not implement Equal method", cryptoPrivKey)
	}

	if !cryptoPrivKeyWithEqual.Equal(compareKeyCryptoPrivKey) {
		return fmt.Errorf("crypto private key %T is not equal to provided crypto private key %T", cryptoPrivKeyWithEqual, compareKeyCryptoPrivKey)
	}

	return nil
}
