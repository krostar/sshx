package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	gssh "github.com/gliderlabs/ssh"
	"go.uber.org/goleak"
	"gotest.tools/v3/assert"
)

func TestMain(m *testing.M) {
	_sshAuthSockFileEnv = "SSHX_AUTH_SOCK"
	goleak.VerifyTestMain(m)
}

const errForTest sentinelError = "an error"

func newTestingSSHServer(t *testing.T, listener net.Listener, rawCallbacks ...interface{}) (func(), <-chan error) {
	var requestHandler map[string]gssh.RequestHandler
	for _, rawCallback := range rawCallbacks {
		if callback, ok := rawCallback.(map[string]gssh.RequestHandler); ok {
			requestHandler = callback
		}
	}

	srv := gssh.Server{
		Addr: listener.Addr().String(),
		LocalPortForwardingCallback: gssh.LocalPortForwardingCallback(func(ctx gssh.Context, host string, port uint32) bool {
			for _, rawCallback := range rawCallbacks {
				if callback, ok := rawCallback.(gssh.LocalPortForwardingCallback); ok {
					return callback(ctx, host, port)
				}
			}

			t.Errorf("unexpected forward fwd %s -> %s:%d", ctx.LocalAddr(), host, port)
			return false
		}),
		Handler: func(session gssh.Session) {
			for _, rawCallback := range rawCallbacks {
				if callback, ok := rawCallback.(gssh.Handler); ok {
					callback(session)
					return
				}
			}

			t.Errorf("unexpected session on %s", session.LocalAddr())
			assert.NilError(t, session.Exit(255))
		},
		ChannelHandlers: map[string]gssh.ChannelHandler{
			"direct-tcpip": gssh.DirectTCPIPHandler,
			"session":      gssh.DefaultSessionHandler,
		},
		RequestHandlers: requestHandler,
	}

	cerr := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil {
			if !errors.Is(err, gssh.ErrServerClosed) {
				cerr <- fmt.Errorf("unable to serve ssh: %w", err)
			}
		}
		cerr <- nil
	}()

	return func() {
		assert.NilError(t, srv.Shutdown(context.Background()))
	}, cerr
}

func runTestingSSHServer(t *testing.T, assertFunc func(*Client), testingServerArgs ...interface{}) {
	t.Helper()

	sshListener, err := net.Listen("tcp", "")
	assert.NilError(t, err)
	sshAddr := sshListener.Addr().String()

	stop, exited := newTestingSSHServer(t, sshListener, testingServerArgs...)

	client, err := NewClient(newTestingClientConfig(t, sshAddr, "anon"))
	assert.NilError(t, err)

	assertFunc(client)

	stop()
	assert.NilError(t, <-exited)
}

func Test_sentinelError_Error(t *testing.T) {
	assert.Equal(t, "foo", sentinelError("foo").Error())
}
