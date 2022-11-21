package sshx

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_NewAgent(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		agentSocketPath := filepath.Join(t.TempDir(), "agent.sock")
		t.Setenv(_sshAuthSockFileEnv, agentSocketPath)
		listener, listenerErr := net.Listen("unix", agentSocketPath)
		assert.NilError(t, listenerErr)

		doneListening := make(chan struct{})
		go func() {
			t.Cleanup(func() { assert.NilError(t, listener.Close()) })

			agentConn, err := listener.Accept()
			assert.NilError(t, err)
			t.Cleanup(func() { assert.NilError(t, agentConn.Close()) })

			close(doneListening)
		}()

		sshAgent, closeSSHAgent, err := NewAgent()
		assert.NilError(t, err)
		assert.Assert(t, sshAgent != nil)
		assert.Assert(t, closeSSHAgent != nil)
		assert.NilError(t, closeSSHAgent())

		<-doneListening
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("env var is unset", func(t *testing.T) {
			assert.NilError(t, os.Unsetenv(_sshAuthSockFileEnv))

			sshAgent, closeSSHAgent, err := NewAgent()
			assert.Assert(t, cmp.ErrorContains(err, "undefined agent unix socket env"))
			assert.Check(t, cmp.Nil(sshAgent))
			assert.Check(t, cmp.Nil(closeSSHAgent))
		})

		t.Run("env var is unset", func(t *testing.T) {
			agentSocketPath := filepath.Join(t.TempDir(), "agent.sock")
			t.Setenv(_sshAuthSockFileEnv, agentSocketPath)

			sshAgent, closeSSHAgent, err := NewAgent()
			assert.Assert(t, cmp.ErrorContains(err, "unable to connect to the agent"))
			assert.Check(t, cmp.Nil(sshAgent))
			assert.Check(t, cmp.Nil(closeSSHAgent))
		})
	})
}

func Test_Agent_UpsertKey(t *testing.T) {
	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey1, err := WrapPrivateKey(rsaPrivKey1)
	assert.NilError(t, err)
	privKey2, err := WrapPrivateKey(rsaPrivKey2)
	assert.NilError(t, err)

	newAgentMock := func(t *testing.T) *agentMock {
		agentMock := new(agentMock)
		agentMock.Test(t)
		t.Cleanup(func() { agentMock.AssertExpectations(t) })
		return agentMock
	}

	t.Run("ok", func(t *testing.T) {
		agentMock := newAgentMock(t)
		sshAgent := Agent{Agent: agentMock}

		{ // the agent already contain the second private key
			agentMock.On("List").Return([]*agent.Key{
				{Format: "rsa", Blob: privKey2.PublicKey().Marshal()},
			}, nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey1}).Return(nil).Once()
		}
		assert.Check(t, sshAgent.UpsertKey(privKey1))

		{ // the agent now contain the two private keys
			agentMock.On("List").Return([]*agent.Key{
				{Format: "rsa", Blob: privKey2.PublicKey().Marshal()},
				{Format: "rsa", Blob: privKey1.PublicKey().Marshal()},
			}, nil).Once()
			agentMock.On("Remove", &agent.Key{Format: "rsa", Blob: privKey2.PublicKey().Marshal()}).Return(nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey2}).Return(nil).Once()
		}
		assert.Check(t, sshAgent.UpsertKey(privKey2))

		{ // the agent now contain the two private keys
			agentMock.On("List").Return([]*agent.Key{
				{Format: "rsa", Blob: privKey2.PublicKey().Marshal()},
				{Format: "rsa", Blob: privKey1.PublicKey().Marshal()},
			}, nil).Once()
			agentMock.On("Remove", &agent.Key{Format: "rsa", Blob: privKey1.PublicKey().Marshal()}).Return(nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey1}).Return(nil).Once()
		}
		assert.Check(t, sshAgent.UpsertKey(privKey1))
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("unable to remove", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, errForTest).Once()
			sshAgent := Agent{Agent: agentMock}

			err := sshAgent.UpsertKey(privKey1)
			assert.Assert(t, cmp.ErrorContains(err, "unable to remove existing private key from agent"))
			assert.Check(t, cmp.Contains(err.Error(), errForTest.Error()))
		})

		t.Run("unable to add", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, nil).Once()
			agentMock.On("Add", mock.Anything).Return(errForTest).Once()
			sshAgent := Agent{Agent: agentMock}

			err := sshAgent.UpsertKey(privKey1)
			assert.Assert(t, cmp.ErrorContains(err, "unable to add private key to agent"))
			assert.Check(t, cmp.Contains(err.Error(), errForTest.Error()))
		})
	})
}

func Test_Agent_UpsertCertificate(t *testing.T) {
	now := time.Now()
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := WrapPrivateKey(rsaPrivKey)
	assert.NilError(t, err)

	t.Run("ok", func(t *testing.T) {
		t.Run("without constraints", func(t *testing.T) {
			sshCert := newTestSSHCertificate(t, privKey, privKey.Signer())
			cert := (*Certificate)(sshCert)

			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey}).Return(nil).Once()
			agentMock.On("Add", agent.AddedKey{
				PrivateKey:  rsaPrivKey,
				Certificate: sshCert,
			}).Return(nil).Once()

			sshAgent := Agent{Agent: agentMock}
			assert.Check(t, sshAgent.UpsertCertificate(privKey, *cert))
		})

		t.Run("with constraints", func(t *testing.T) {
			sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
				cert.ValidAfter = uint64(now.Add(-time.Minute).Unix())
				cert.ValidBefore = uint64(now.Add(time.Minute).Unix())
			})
			cert := (Certificate)(*sshCert)

			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey}).Return(nil).Once()
			agentMock.On("Add", mock.MatchedBy(func(key agent.AddedKey) bool {
				match := agent.AddedKey{PrivateKey: rsaPrivKey, Certificate: sshCert, LifetimeSecs: uint32(time.Minute.Seconds())}
				return cmp.DeepEqual(match, key,
					gocmp.FilterPath(
						func(path gocmp.Path) bool { return path.String() == "Certificate" },
						gocmp.Comparer(func(x, y *ssh.Certificate) bool {
							return cmpCertificate((*Certificate)(x), (*Certificate)(y))().Success()
						}),
					),
					gocmp.FilterPath(
						func(path gocmp.Path) bool { return path.String() == "LifetimeSecs" },
						gocmp.Comparer(func(x, y uint32) bool { return x-y < 3 }),
					),
				)().Success()
			})).Return(nil).Once()

			sshAgent := Agent{Agent: agentMock}
			assert.NilError(t, sshAgent.UpsertCertificate(privKey, cert))
		})
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("invalid cert", func(t *testing.T) {
			sshCert := newTestSSHCertificate(t, privKey, privKey.Signer(), func(cert *ssh.Certificate) {
				cert.ValidAfter = uint64(time.Now().Add(time.Hour).Unix())
			})
			cert := (Certificate)(*sshCert)
			sshAgent := Agent{Agent: newAgentMock(t)}

			err := sshAgent.UpsertCertificate(privKey, cert)
			assert.ErrorContains(t, err, "invalid certificate")
		})

		t.Run("unable to upsert key", func(t *testing.T) {
			sshCert := newTestSSHCertificate(t, privKey, privKey.Signer())
			cert := (Certificate)(*sshCert)

			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, errForTest).Once()

			sshAgent := Agent{Agent: agentMock}
			err := sshAgent.UpsertCertificate(privKey, cert)
			assert.ErrorContains(t, err, "unable to upsert private key")
		})

		t.Run("unable to add key", func(t *testing.T) {
			sshCert := newTestSSHCertificate(t, privKey, privKey.Signer())
			cert := (Certificate)(*sshCert)

			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, nil).Once()
			agentMock.On("Add", agent.AddedKey{PrivateKey: rsaPrivKey}).Return(nil).Once()
			agentMock.On("Add", mock.Anything).Return(errForTest).Once()

			sshAgent := Agent{Agent: agentMock}
			err := sshAgent.UpsertCertificate(privKey, cert)
			assert.ErrorContains(t, err, "unable to add certificate to agent")
		})
	})
}

func Test_Agent_GetSignerMatchingPublicKey(t *testing.T) {
	privKey1 := newTestPrivateKey(t)
	privKey2 := newTestPrivateKey(t)

	t.Run("ok", func(t *testing.T) {
		signerMock1 := newSignerMock(t)
		signerMock1.On("PublicKey").Return(privKey1.PublicKey()).Once()
		signerMock2 := newSignerMock(t)
		signerMock2.On("PublicKey").Return(privKey2.PublicKey()).Once()

		agentMock := newAgentMock(t)
		agentMock.On("Signers").Return([]ssh.Signer{signerMock2, signerMock1}, nil).Once()
		sshAgent := Agent{Agent: agentMock}

		signer, err := sshAgent.GetSignerMatchingPublicKey(privKey1.PublicKey())
		assert.NilError(t, err)
		assert.Equal(t, signer, signerMock1)
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("unable to get signers", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("Signers").Return(nil, errForTest).Once()
			sshAgent := Agent{Agent: agentMock}

			signer, err := sshAgent.GetSignerMatchingPublicKey(privKey1.PublicKey())
			assert.Assert(t, cmp.ErrorContains(err, "unable to get signers in agent"))
			assert.Check(t, cmp.Contains(err.Error(), errForTest.Error()))
			assert.Check(t, cmp.Nil(signer))
		})

		t.Run("no matching signers", func(t *testing.T) {
			signerMock1 := newSignerMock(t)
			signerMock1.On("PublicKey").Return(privKey2.PublicKey()).Once()
			signerMock2 := newSignerMock(t)
			signerMock2.On("PublicKey").Return(privKey2.PublicKey()).Once()

			agentMock := newAgentMock(t)
			agentMock.On("Signers").Return([]ssh.Signer{signerMock2, signerMock1}, nil).Once()
			sshAgent := Agent{Agent: agentMock}

			signer, err := sshAgent.GetSignerMatchingPublicKey(privKey1.PublicKey())
			assert.ErrorIs(t, err, ErrSignerNotFound)
			assert.Check(t, cmp.Nil(signer))
		})
	})
}

func Test_Agent_RemoveMatchingPublicKey(t *testing.T) {
	privKey1 := newTestPrivateKey(t)
	privKey2 := newTestPrivateKey(t)

	t.Run("ok", func(t *testing.T) {
		t.Run("nothing in the agent", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, nil).Once()
			sshAgent := Agent{Agent: agentMock}
			assert.NilError(t, sshAgent.RemoveMatchingPublicKey(privKey1.PublicKey()))
		})

		t.Run("key found in the agent", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return([]*agent.Key{
				{Format: "rsa", Blob: privKey2.PublicKey().Marshal()},
				{Format: "rsa", Blob: privKey1.PublicKey().Marshal()},
				{Format: "rsa", Blob: privKey2.PublicKey().Marshal()},
			}, nil).Once()
			agentMock.On("Remove", &agent.Key{Format: "rsa", Blob: privKey2.PublicKey().Marshal()}).Return(nil).Twice()
			sshAgent := Agent{Agent: agentMock}
			assert.NilError(t, sshAgent.RemoveMatchingPublicKey(privKey2.PublicKey()))
		})
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("unable to list", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return(nil, errForTest).Once()
			sshAgent := Agent{Agent: agentMock}

			err := sshAgent.RemoveMatchingPublicKey(privKey1.PublicKey())
			assert.Assert(t, cmp.ErrorContains(err, "unable to list keys in agent"))
			assert.Check(t, cmp.Contains(err.Error(), errForTest.Error()))
		})

		t.Run("unable to remove", func(t *testing.T) {
			agentMock := newAgentMock(t)
			agentMock.On("List").Return([]*agent.Key{{Format: "rsa", Blob: privKey1.PublicKey().Marshal()}}, nil).Once()
			agentMock.On("Remove", mock.Anything).Return(errForTest).Once()
			sshAgent := Agent{Agent: agentMock}

			err := sshAgent.RemoveMatchingPublicKey(privKey1.PublicKey())
			assert.Assert(t, cmp.ErrorContains(err, "unable to remove key from agent"))
			assert.Check(t, cmp.Contains(err.Error(), errForTest.Error()))
		})
	})
}

type agentMock struct{ mock.Mock }

func newAgentMock(t *testing.T) *agentMock {
	agentMock := new(agentMock)
	agentMock.Test(t)
	t.Cleanup(func() { agentMock.AssertExpectations(t) })
	return agentMock
}

func (m *agentMock) List() ([]*agent.Key, error) {
	args := m.Called()

	var keys []*agent.Key
	if arg := args.Get(0); arg != nil {
		keys = arg.([]*agent.Key)
	}

	return keys, args.Error(1)
}

func (m *agentMock) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	args := m.Called(key, data)

	var signature *ssh.Signature
	if arg := args.Get(0); arg != nil {
		signature = arg.(*ssh.Signature)
	}

	return signature, args.Error(1)
}

func (m *agentMock) Add(key agent.AddedKey) error {
	return m.Called(key).Error(0)
}

func (m *agentMock) Remove(key ssh.PublicKey) error {
	return m.Called(key).Error(0)
}

func (m *agentMock) RemoveAll() error {
	return m.Called().Error(0)
}

func (m *agentMock) Lock(passphrase []byte) error {
	return m.Called(passphrase).Error(0)
}

func (m *agentMock) Unlock(passphrase []byte) error {
	return m.Called(passphrase).Error(0)
}

func (m *agentMock) Signers() ([]ssh.Signer, error) {
	args := m.Called()

	var signers []ssh.Signer
	if arg := args.Get(0); arg != nil {
		signers = arg.([]ssh.Signer)
	}

	return signers, args.Error(1)
}

type signerMock struct{ mock.Mock }

func newSignerMock(t *testing.T) *signerMock {
	signerMock := new(signerMock)
	signerMock.Test(t)
	t.Cleanup(func() { signerMock.AssertExpectations(t) })
	return signerMock
}

func (m *signerMock) PublicKey() ssh.PublicKey {
	args := m.Called()

	var pubKey ssh.PublicKey
	if arg := args.Get(0); arg != nil {
		pubKey = arg.(ssh.PublicKey)
	}

	return pubKey
}

func (m *signerMock) Sign(randomReader io.Reader, data []byte) (*ssh.Signature, error) {
	args := m.Called(randomReader, data)

	var signature *ssh.Signature
	if arg := args.Get(0); arg != nil {
		signature = arg.(*ssh.Signature)
	}

	return signature, args.Error(1)
}
