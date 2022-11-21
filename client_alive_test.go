package sshx

import (
	"context"
	"fmt"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_Client_CheckLivenessUntilNotAlive(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var called uint

		runTestingSSHServer(t,
			func(client *Client) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
				defer cancel()

				err := client.CheckLivenessUntilNotAlive(ctx, time.Millisecond*750, 1)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Assert(t, client.Close())
			},
			map[string]gssh.RequestHandler{
				"keepalive@golang.org": func(gssh.Context, *gssh.Server, *ssh.Request) (bool, []byte) {
					called++
					return false, nil
				},
			},
		)

		assert.Check(t, func() cmp.Result {
			var err error
			if called < 1 || called > 3 {
				err = fmt.Errorf("expected function to be called between 1 and 3, called %d", called)
			}
			return cmp.ResultFromError(err)
		})
	})

	t.Run("ko", func(t *testing.T) {
		runTestingSSHServer(t,
			func(client *Client) {
				assert.NilError(t, client.Close())

				err := client.CheckLivenessUntilNotAlive(context.Background(), time.Millisecond*100, 5)
				assert.Assert(t, cmp.ErrorContains(err, "check failed 5 time consecutively"))
			},
		)
	})
}

func Test_Client_IsAlive(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var called bool

		runTestingSSHServer(t,
			func(client *Client) {
				assert.NilError(t, client.IsAlive())
				assert.Check(t, called)
				assert.NilError(t, client.Close())
			},
			map[string]gssh.RequestHandler{
				"keepalive@golang.org": func(ctx gssh.Context, srv *gssh.Server, req *ssh.Request) (bool, []byte) {
					assert.Check(t, cmp.Equal("keepalive@golang.org", req.Type))
					assert.Check(t, req.WantReply)
					assert.Check(t, cmp.Len(req.Payload, 0))
					called = true
					return false, nil
				},
			},
		)
	})

	t.Run("ko", func(t *testing.T) {
		runTestingSSHServer(t, func(client *Client) {
			assert.Check(t, client.Close())

			err := client.IsAlive()
			assert.Assert(t, cmp.ErrorContains(err, "unable to send keepalive request"))
		})
	})
}
