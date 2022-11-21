package sshx

import (
	"crypto/dsa" //nolint:staticcheck // to handle all keys that are already handled by ssh package we have to handle deprecated dsa keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_WrapPrivateKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		runForEachTypeOfPrivateKey(t, func(t *testing.T, rawPrivKey interface{}, privKey PrivateKey) {
			assert.Check(t, cmp.DeepEqual(rawPrivKey, privKey.Raw(), gocmp.AllowUnexported(big.Int{})))
		})

		t.Run("dsa", func(t *testing.T) {
			var rawPrivKey dsa.PrivateKey
			assert.NilError(t, dsa.GenerateParameters(&rawPrivKey.Parameters, rand.Reader, dsa.L1024N160))
			assert.NilError(t, dsa.GenerateKey(&rawPrivKey, rand.Reader))

			privKey, err := WrapPrivateKey(&rawPrivKey)
			assert.NilError(t, err)
			assert.Check(t, cmp.DeepEqual(&rawPrivKey, privKey.Raw(), gocmp.AllowUnexported(big.Int{})))
		})
	})

	t.Run("ko", func(t *testing.T) {
		privKey, err := WrapPrivateKey(42)
		assert.ErrorContains(t, err, "unable to parse ssh public key")
		assert.Check(t, cmp.Nil(privKey))
	})
}

func Test_NewPrivateKeyFromPEMBytes(t *testing.T) {
	providedRSAPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	providedPrivKey, err := WrapPrivateKey(providedRSAPrivKey)
	assert.NilError(t, err)

	getRSAPrivateKeyPEMBlocks := func(rsaPrivKey *rsa.PrivateKey) *pem.Block {
		pemBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey),
		}
		return pemBlock
	}

	t.Run("without passphrase", func(t *testing.T) {
		privKey, err := NewPrivateKeyFromPEMBytes(pem.EncodeToMemory(getRSAPrivateKeyPEMBlocks(providedRSAPrivKey)), nil)
		assert.NilError(t, err)
		assert.Assert(t, cmpPrivateKey(providedPrivKey, privKey))
	})

	t.Run("with passphrase", func(t *testing.T) {
		const passphrase = "get secured!"
		getRSAPrivateKeyPEMBlocks := func(t *testing.T) *pem.Block {
			pemBlock := getRSAPrivateKeyPEMBlocks(providedRSAPrivKey)
			pemBlock, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(passphrase), x509.PEMCipherAES256) //nolint:staticcheck //insecurity in tests is tolerated
			assert.NilError(t, err)
			return pemBlock
		}

		t.Run("with correct passphrase", func(t *testing.T) {
			privKey, err := NewPrivateKeyFromPEMBytes(pem.EncodeToMemory(getRSAPrivateKeyPEMBlocks(t)),
				func() ([]byte, error) { return []byte(passphrase), nil },
			)
			assert.NilError(t, err)
			assert.Check(t, cmpPrivateKey(providedPrivKey, privKey))
		})

		t.Run("without passphrase getter", func(t *testing.T) {
			privKey, err := NewPrivateKeyFromPEMBytes(pem.EncodeToMemory(getRSAPrivateKeyPEMBlocks(t)), nil)
			assert.ErrorContains(t, err, "unable to parse private key")
			assert.Check(t, func() cmp.Result {
				if perr := new(ssh.PassphraseMissingError); errors.As(err, &perr) {
					return cmp.ResultSuccess
				}
				return cmp.ResultFromError(err)
			})
			assert.Check(t, cmp.Nil(privKey))
		})

		t.Run("without the correct passphrase", func(t *testing.T) {
			privKey, err := NewPrivateKeyFromPEMBytes(pem.EncodeToMemory(getRSAPrivateKeyPEMBlocks(t)),
				func() ([]byte, error) { return []byte("not correct"), nil },
			)
			assert.ErrorContains(t, err, "unable to parse private key with passphrase")
			assert.ErrorContains(t, err, "decryption password incorrect")
			assert.Check(t, cmp.Nil(privKey))
		})

		t.Run("with error retrieving the passphrase", func(t *testing.T) {
			privKey, err := NewPrivateKeyFromPEMBytes(pem.EncodeToMemory(getRSAPrivateKeyPEMBlocks(t)),
				func() ([]byte, error) { return nil, errForTest },
			)
			assert.ErrorContains(t, err, "unable to get passphrase")
			assert.ErrorIs(t, err, errForTest)
			assert.Check(t, cmp.Nil(privKey))
		})
	})
}

func Test_NewPrivateKeyFromPEMFile(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NilError(t, err)

		filePath := filepath.Join(t.TempDir(), "rsa.key")
		assert.NilError(t, os.WriteFile(filePath, pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey),
		}), 0o400))

		privKey, err := NewPrivateKeyFromPEMFile(filePath, nil)
		assert.NilError(t, err)
		assert.Check(t, cmp.DeepEqual(rsaPrivKey, privKey.Raw()))
	})

	t.Run("ko", func(t *testing.T) {
		privKey, err := NewPrivateKeyFromPEMFile("notfound.key", nil)
		assert.Assert(t, cmp.ErrorContains(err, ""))
		assert.Check(t, cmp.Contains(err.Error(), "unable to read"))
		assert.Check(t, cmp.ErrorIs(err, fs.ErrNotExist))
		assert.Check(t, cmp.Nil(privKey))
	})
}

func Test_privateKey_Equal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		runForEachTypeOfPrivateKey(t, func(t *testing.T, rawPrivKey interface{}, privKey PrivateKey) {
			samePrivKey, err := WrapPrivateKey(rawPrivKey)
			assert.NilError(t, err)
			assert.Check(t, privKey.Equal(samePrivKey))
		})
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("dsa does not implement equal method", func(t *testing.T) {
			var rawPrivKey dsa.PrivateKey
			assert.NilError(t, dsa.GenerateParameters(&rawPrivKey.Parameters, rand.Reader, dsa.L1024N160))
			assert.NilError(t, dsa.GenerateKey(&rawPrivKey, rand.Reader))

			privKey, err := WrapPrivateKey(&rawPrivKey)
			assert.NilError(t, err)
			samePrivKey, err := WrapPrivateKey(&rawPrivKey)
			assert.NilError(t, err)

			assert.ErrorContains(t, privKey.Equal(samePrivKey), "crypto private key *dsa.PrivateKey does not implement Equal method")
		})

		t.Run("two different keys are not equal", func(t *testing.T) {
			rawPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NilError(t, err)
			rawPrivKey2, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NilError(t, err)

			privKey1, err := WrapPrivateKey(rawPrivKey1)
			assert.NilError(t, err)
			privKey2, err := WrapPrivateKey(rawPrivKey2)
			assert.NilError(t, err)

			assert.ErrorContains(t, privKey1.Equal(privKey2), "crypto private key *rsa.PrivateKey is not equal to provided crypto private key")
		})
	})
}

func runForEachTypeOfPrivateKey(t *testing.T, test func(t *testing.T, rawPrivKey interface{}, privKey PrivateKey)) {
	for name, getPrivKey := range map[string]func(t *testing.T) interface{}{
		"rsa": func(t *testing.T) interface{} {
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NilError(t, err)
			return privKey
		},
		"ecdsa": func(t *testing.T) interface{} {
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			assert.NilError(t, err)
			return privKey
		},
		"ed25519": func(t *testing.T) interface{} {
			_, privKey, err := ed25519.GenerateKey(rand.Reader)
			assert.NilError(t, err)
			return privKey
		},
	} {
		t.Run(name, func(t *testing.T) {
			rawPrivKey := getPrivKey(t)
			privKey, err := WrapPrivateKey(rawPrivKey)
			assert.NilError(t, err)
			test(t, rawPrivKey, privKey)
		})
	}
}

func newTestPrivateKey(t *testing.T) PrivateKey {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := WrapPrivateKey(rsaPrivKey)
	assert.NilError(t, err)
	return privKey
}

func cmpPrivateKey(x, y PrivateKey) cmp.Comparison {
	return func() cmp.Result {
		return cmp.ResultFromError(x.Equal(y))
	}
}
