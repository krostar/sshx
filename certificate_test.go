package sshx

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_NewCertificateFromOpenSSHAuthorizedKeyBytes(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privKey := newTestPrivateKey(t)
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer())

		cert, err := NewCertificateFromOpenSSHAuthorizedKeyBytes(ssh.MarshalAuthorizedKey(sshCert))
		assert.NilError(t, err)
		assert.Check(t, cmpCertificate(cert, (*Certificate)(sshCert)))
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("not respecting authorized-key format", func(t *testing.T) {
			cert, err := NewCertificateFromOpenSSHAuthorizedKeyBytes([]byte("42"))
			assert.Check(t, cmp.Nil(cert))
			assert.Assert(t, cmp.ErrorContains(err, "unable to parse ssh certificate from raw openssh certificate"))
		})

		t.Run("respecting authorized-key format but not a certificate", func(t *testing.T) {
			privKey := newTestPrivateKey(t)
			cert, err := NewCertificateFromOpenSSHAuthorizedKeyBytes(ssh.MarshalAuthorizedKey(privKey.PublicKey()))
			assert.Check(t, cmp.Nil(cert))
			assert.Assert(t, cmp.ErrorContains(err, "parsed authorized key is not a certificate"))
		})
	})
}

func Test_NewCertificateFromOpenSSHAuthorizedKeyFile(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privKey := newTestPrivateKey(t)
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer())

		filePath := filepath.Join(t.TempDir(), "rsa-cert.pub")
		assert.NilError(t, os.WriteFile(filePath, ssh.MarshalAuthorizedKey(sshCert), 0o400))

		cert, err := NewCertificateFromOpenSSHAuthorizedKeyFile(filePath)
		assert.NilError(t, err)
		assert.Check(t, cmpCertificate(cert, (*Certificate)(sshCert)))
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("unable to read", func(t *testing.T) {
			cert, err := NewCertificateFromOpenSSHAuthorizedKeyFile("notfound-cert.pub")
			assert.Assert(t, cmp.ErrorContains(err, "unable to read"))
			assert.ErrorIs(t, err, fs.ErrNotExist)
			assert.Check(t, cmp.Nil(cert))
		})

		t.Run("invalid cert", func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "invalid.file")
			assert.NilError(t, os.WriteFile(filePath, []byte("hello"), 0o400))

			cert, err := NewCertificateFromOpenSSHAuthorizedKeyFile(filePath)
			assert.Assert(t, cmp.ErrorContains(err, "unable to parse ssh certificate"))
			assert.Check(t, cmp.Nil(cert))
		})
	})
}

func Test_Certificate_IsValid(t *testing.T) {
	privKey := newTestPrivateKey(t)
	now := time.Now()

	t.Run("no validity constraints", func(t *testing.T) {
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
			cert.ValidAfter = 0
			cert.ValidBefore = 0
		})
		cert := (*Certificate)(sshCert)
		assert.NilError(t, cert.IsValid())
	})

	t.Run("validity constraints", func(t *testing.T) {
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
			cert.ValidBefore = uint64(now.Add(time.Hour).Unix())
			cert.ValidAfter = uint64(now.Add(-time.Hour).Unix())
		})
		cert := (*Certificate)(sshCert)
		assert.NilError(t, cert.IsValid())
	})

	t.Run("not yet valid", func(t *testing.T) {
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
			cert.ValidAfter = uint64(now.Add(time.Hour).Unix())
		})
		cert := (*Certificate)(sshCert)
		err := cert.IsValid()
		assert.Assert(t, cmp.ErrorContains(err, "certificate validity starts in"))
	})

	t.Run("expired", func(t *testing.T) {
		sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
			cert.ValidBefore = uint64(now.Add(-time.Hour).Unix())
		})
		cert := (*Certificate)(sshCert)
		assert.Assert(t, cmp.ErrorContains(cert.IsValid(), "certificate validity expired"))
	})
}

func newTestSSHCertificate(t *testing.T, privKey PrivateKey, signer ssh.Signer, setups ...func(cert *ssh.Certificate)) *ssh.Certificate {
	cert := &ssh.Certificate{
		Nonce:           []byte{}, // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
		Key:             privKey.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"foo", "bar"},
		Permissions: ssh.Permissions{ // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
			CriticalOptions: make(map[string]string),
			Extensions:      make(map[string]string),
		},
		Reserved:     []byte{}, // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
		SignatureKey: privKey.PublicKey(),
	}
	for _, setup := range setups {
		setup(cert)
	}
	assert.NilError(t, cert.SignCert(rand.Reader, signer))
	return cert
}

func cmpCertificate(x, y *Certificate) cmp.Comparison {
	return func() cmp.Result {
		// compare public keys first
		if err := WrapSSHPublicKey(x.Key).Equal(WrapSSHPublicKey(y.Key)); err != nil {
			return cmp.ResultFromError(fmt.Errorf("x.Key != y.Key: %v", err))
		}
		// then compare the rest
		return cmp.DeepEqual(x, y,
			gocmp.AllowUnexported(big.Int{}),
			gocmp.FilterPath(func(path gocmp.Path) bool { return path.String() == "Key" }, gocmp.Ignore()),
		)()
	}
}
