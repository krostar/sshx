package sshx

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_NewClient(t *testing.T) {
	t.Run("run with invalid config", func(t *testing.T) {
		_, err := NewClient(new(ClientConfig))
		assert.ErrorContains(t, err, "invalid ssh config")
	})

	t.Run("run with no bridge", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			runTestingSSHServer(t, func(client *Client) {
				assert.Check(t, client.Client != nil)
				assert.Check(t, cmp.Nil(client.bridge))
				assert.Check(t, len(client.addr) != 0)

				session, err := client.NewSession()
				assert.NilError(t, err)
				assert.NilError(t, session.Run("foo"))
				assert.Check(t, client.Close())
			}, gssh.Handler(func(session gssh.Session) {
				assert.Equal(t, "foo", session.RawCommand())
			}))
		})

		t.Run("ssh server gone", func(t *testing.T) {
			t.Run("dial", func(t *testing.T) {
				sshListener, err := net.Listen("tcp", "")
				assert.NilError(t, err)
				assert.NilError(t, sshListener.Close())

				client, err := NewClient(newTestingClientConfig(t, sshListener.Addr().String(), "anon"))
				assert.Check(t, cmp.ErrorContains(err, "unable to dial"))
				assert.Check(t, cmp.Nil(client))
			})

			t.Run("read / write stuck", func(t *testing.T) {
				sshListener, listenerErr := net.Listen("tcp", "")
				assert.NilError(t, listenerErr)

				ctx, cancel := context.WithCancel(context.Background())

				go func() {
					conn, err := sshListener.Accept()
					assert.NilError(t, err)
					// block handshake by not answering anything
					<-ctx.Done()
					assert.Check(t, conn.Close())
				}()

				cfg := newTestingClientConfig(t, sshListener.Addr().String(), "anon")
				cfg.SSHClientConfig.Timeout = time.Millisecond * 100
				client, err := NewClient(cfg)
				assert.Check(t, cmp.Nil(client))
				assert.Check(t, cmp.ErrorContains(err, "unable to create client conn"))

				cancel()
				assert.Check(t, cmp.Nil(sshListener.Close()))
			})
		})
	})

	t.Run("run with bridges", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			var commands []string

			ssh1Listener, listenerErr := net.Listen("tcp", "")
			assert.NilError(t, listenerErr)
			ssh2Listener, listenerErr := net.Listen("tcp", "")
			assert.NilError(t, listenerErr)
			ssh3Listener, listenerErr := net.Listen("tcp", "")
			assert.NilError(t, listenerErr)

			stopSSH1, ssh1Exited := newTestingSSHServer(t, ssh1Listener,
				gssh.LocalPortForwardingCallback(func(ctx gssh.Context, host string, port uint32) bool {
					hostAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("[%s]:%d", host, port))
					assert.Check(t, err)
					return ssh2Listener.Addr().String() == hostAddr.String()
				}),
			)
			stopSSH2, ssh2Exited := newTestingSSHServer(t, ssh2Listener,
				gssh.LocalPortForwardingCallback(func(ctx gssh.Context, host string, port uint32) bool {
					hostAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("[%s]:%d", host, port))
					assert.Check(t, err)
					return ssh3Listener.Addr().String() == hostAddr.String()
				}),
			)
			stopSSH3, ssh3Exited := newTestingSSHServer(t, ssh3Listener,
				gssh.Handler(func(session gssh.Session) {
					commands = append(commands, session.RawCommand())
				}),
			)

			cfg := newTestingClientConfig(t, ssh3Listener.Addr().String(), "ssh3")
			cfg.Bridge = newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
			cfg.Bridge.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")

			client, err := NewClient(cfg)
			assert.NilError(t, err)

			session, err := client.NewSession()
			assert.NilError(t, err)
			assert.NilError(t, session.Run("foo"))
			assert.DeepEqual(t, []string{"foo"}, commands)
			assert.NilError(t, client.Close())

			stopSSH3()
			assert.NilError(t, <-ssh3Exited)
			stopSSH2()
			assert.NilError(t, <-ssh2Exited)
			stopSSH1()
			assert.NilError(t, <-ssh1Exited)
		})

		t.Run("ko", func(t *testing.T) {
			t.Run("unable to create bridge", func(t *testing.T) {
				ssh1Listener, listenerErr := net.Listen("tcp", "")
				assert.NilError(t, listenerErr)
				ssh2Listener, listenerErr := net.Listen("tcp", "")
				assert.NilError(t, listenerErr)

				ctx, cancel := context.WithCancel(context.Background())

				go func() {
					conn, err := ssh1Listener.Accept()
					assert.NilError(t, err)
					// block handshake by not answering anything
					<-ctx.Done()
					assert.Check(t, conn.Close())
				}()

				cfg := newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
				cfg.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")
				cfg.Bridge.SSHClientConfig.Timeout = time.Millisecond * 100
				client, err := NewClient(cfg)
				assert.Check(t, cmp.Nil(client))
				assert.Check(t, cmp.ErrorContains(err, "unable to create bridge"))

				cancel()
				assert.NilError(t, ssh2Listener.Close())
				assert.NilError(t, ssh1Listener.Close())
			})

			t.Run("unable to create conn through bridge", func(t *testing.T) {
				ssh1Listener, err := net.Listen("tcp", "")
				assert.NilError(t, err)
				ssh2Listener, err := net.Listen("tcp", "")
				assert.NilError(t, err)
				assert.Check(t, ssh2Listener.Close())

				stopSSH1, ssh1Exited := newTestingSSHServer(t, ssh1Listener,
					gssh.LocalPortForwardingCallback(func(gssh.Context, string, uint32) bool { return true }),
				)

				cfg := newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
				cfg.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")
				client, err := NewClient(cfg)
				assert.Check(t, cmp.Nil(client))
				assert.Assert(t, cmp.ErrorContains(err, "unable to dial"))
				assert.Check(t, cmp.Contains(err.Error(), "through bridge"))

				stopSSH1()
				assert.Check(t, <-ssh1Exited)
			})

			t.Run("unable to create conn through bridge", func(t *testing.T) {
				ssh1Listener, listenerErr := net.Listen("tcp", "")
				assert.NilError(t, listenerErr)
				ssh2Listener, listenerErr := net.Listen("tcp", "")
				assert.NilError(t, listenerErr)

				stopSSH1, ssh1Exited := newTestingSSHServer(t, ssh1Listener,
					gssh.LocalPortForwardingCallback(func(gssh.Context, string, uint32) bool { return true }),
				)
				ctx, cancel := context.WithCancel(context.Background())

				go func() {
					conn, err := ssh2Listener.Accept()
					assert.NilError(t, err)
					// block handshake by not answering anything
					<-ctx.Done()
					assert.Check(t, conn.Close())
				}()

				cfg := newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
				cfg.SSHClientConfig.Timeout = time.Millisecond * 100
				cfg.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")
				client, err := NewClient(cfg)
				assert.Check(t, cmp.Nil(client))
				assert.Assert(t, cmp.ErrorContains(err, "unable to create client"))
				assert.Check(t, cmp.Contains(err.Error(), "through bridge"))

				cancel()
				stopSSH1()
				assert.NilError(t, <-ssh1Exited)
				assert.NilError(t, ssh2Listener.Close())
			})
		})
	})
}

func Test_Client_Close(t *testing.T) {
	t.Run("no bridge", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			runTestingSSHServer(t, func(client *Client) {
				assert.NilError(t, client.Close())
			})
		})

		t.Run("ko", func(t *testing.T) {
			runTestingSSHServer(t, func(client *Client) {
				assert.Check(t, client.Close())
				assert.ErrorContains(t, client.Close(), "unable to close")
			})
		})
	})

	t.Run("with bridges", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ssh1Listener, err := net.Listen("tcp", "")
			assert.NilError(t, err)
			ssh2Listener, err := net.Listen("tcp", "")
			assert.NilError(t, err)

			stopSSH1, ssh1Exited := newTestingSSHServer(t, ssh1Listener,
				gssh.LocalPortForwardingCallback(func(gssh.Context, string, uint32) bool { return true }),
			)
			stopSSH2, ssh2Exited := newTestingSSHServer(t, ssh2Listener)

			cfg := newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
			cfg.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")

			client, err := NewClient(cfg)
			assert.NilError(t, err)
			assert.Check(t, client.Close())

			stopSSH2()
			assert.Check(t, <-ssh2Exited)
			stopSSH1()
			assert.Check(t, <-ssh1Exited)
		})

		t.Run("ko", func(t *testing.T) {
			ssh1Listener, err := net.Listen("tcp", "")
			assert.NilError(t, err)
			ssh2Listener, err := net.Listen("tcp", "")
			assert.NilError(t, err)

			stopSSH1, ssh1Exited := newTestingSSHServer(t, ssh1Listener,
				gssh.LocalPortForwardingCallback(func(gssh.Context, string, uint32) bool { return true }),
			)
			stopSSH2, ssh2Exited := newTestingSSHServer(t, ssh2Listener)

			cfg := newTestingClientConfig(t, ssh2Listener.Addr().String(), "ssh2")
			cfg.Bridge = newTestingClientConfig(t, ssh1Listener.Addr().String(), "ssh1")

			client, err := NewClient(cfg)
			assert.NilError(t, err)
			assert.Check(t, client.Close())
			assert.Check(t, cmp.ErrorContains(client.Close(), "use of closed network connection"))

			stopSSH2()
			assert.Check(t, <-ssh2Exited)
			stopSSH1()
			assert.Check(t, <-ssh1Exited)
		})
	})
}
