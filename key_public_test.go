package sshx

import (
	"crypto/dsa" //nolint:staticcheck // to handle all keys that are already handled by ssh package we have to handle deprecated dsa keys
	"crypto/rand"
	"crypto/rsa"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_NewPublicKeyFromOpenSSHAuthorizedKeyBytes(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privKey := newTestPrivateKey(t)
		pubKey, err := NewPublicKeyFromOpenSSHAuthorizedKeyBytes(ssh.MarshalAuthorizedKey(privKey.PublicKey()))
		assert.NilError(t, err)
		assert.Check(t, cmpPublicKey(privKey.PublicKey(), pubKey))
	})

	t.Run("ko", func(t *testing.T) {
		pubKey, err := NewPublicKeyFromOpenSSHAuthorizedKeyBytes([]byte("hello world"))
		assert.ErrorContains(t, err, "unable to parse ssh public key from raw openssh public key")
		assert.Check(t, cmp.Nil(pubKey))
	})
}

func Test_NewPublicKeyFromOpenSSHAuthorizedKeyFile(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privKey := newTestPrivateKey(t)
		filePath := filepath.Join(t.TempDir(), "rsa.key.pub")
		assert.NilError(t, os.WriteFile(filePath, ssh.MarshalAuthorizedKey(privKey.PublicKey()), 0o400))

		pubKey, err := NewPublicKeyFromOpenSSHAuthorizedKeyFile(filePath)
		assert.NilError(t, err)
		assert.Check(t, cmpPublicKey(pubKey, privKey.PublicKey()))
	})

	t.Run("ko", func(t *testing.T) {
		pubKey, err := NewPublicKeyFromOpenSSHAuthorizedKeyFile("notfound.key.pub")
		assert.ErrorContains(t, err, "unable to read")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		assert.Check(t, cmp.Nil(pubKey))
	})
}

func Test_publicKey_Equal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		runForEachTypeOfPrivateKey(t, func(t *testing.T, rawPrivKey any, privKey PrivateKey) {
			assert.NilError(t, privKey.PublicKey().Equal(privKey.PublicKey()))
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

			assert.ErrorContains(t, privKey.PublicKey().Equal(samePrivKey.PublicKey()), "crypto public key *dsa.PublicKey does not implement Equal method")
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

			assert.ErrorContains(t, privKey1.PublicKey().Equal(privKey2.PublicKey()), "crypto public key *rsa.PublicKey is not equal to provided crypto public key")
		})
	})
}

func Test_publicKey_String(t *testing.T) {
	rawPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := WrapPrivateKey(rawPrivKey)
	assert.NilError(t, err)

	str := privKey.PublicKey().String()
	assert.Check(t, strings.HasPrefix(str, "ssh-rsa "))
}

func cmpPublicKey(x, y PublicKey) cmp.Comparison {
	return func() cmp.Result {
		return cmp.ResultFromError(x.Equal(y))
	}
}
