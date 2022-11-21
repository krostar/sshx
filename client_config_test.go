package sshx

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
)

func Test_ClientConfig_Validate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		assert.NilError(t, (&ClientConfig{
			Addr:            "1",
			SSHClientConfig: ssh.ClientConfig{Timeout: time.Second},
			Bridge: &ClientConfig{
				Addr:            "2",
				SSHClientConfig: ssh.ClientConfig{Timeout: time.Second},
			},
		}).Validate())
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("empty addr", func(t *testing.T) {
			err := (&ClientConfig{
				SSHClientConfig: ssh.ClientConfig{Timeout: time.Second},
			}).Validate()
			assert.ErrorContains(t, err, "empty addr")
		})

		t.Run("empty network timeout", func(t *testing.T) {
			err := (&ClientConfig{
				Addr: "1",
			}).Validate()
			assert.ErrorContains(t, err, "empty network timeout")
		})

		t.Run("bridge invalid", func(t *testing.T) {
			err := (&ClientConfig{
				Addr:            "1",
				SSHClientConfig: ssh.ClientConfig{Timeout: time.Second},
				Bridge:          &ClientConfig{},
			}).Validate()
			assert.ErrorContains(t, err, "bridge of 1 config is invalid: empty addr")
		})
	})
}

func newTestingClientConfig(t *testing.T, addr, user string) *ClientConfig {
	t.Helper()

	return &ClientConfig{
		Addr: addr,
		SSHClientConfig: ssh.ClientConfig{
			User:            user,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // its a test we don't care
			Timeout:         time.Minute,
		},
	}
}
