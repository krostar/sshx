package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type clientTCPConnWithSoftDeadline struct {
	net.Conn
	timeout time.Duration
}

func (c clientTCPConnWithSoftDeadline) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, fmt.Errorf("unable to set read deadline: %w", err)
	}
	return c.Conn.Read(b)
}

func (c clientTCPConnWithSoftDeadline) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, fmt.Errorf("unable to set write deadline: %w", err)
	}
	return c.Conn.Write(b)
}

type clientTCPConnWithHardDeadline struct {
	net.Conn
	timeout time.Duration
}

func (c clientTCPConnWithHardDeadline) Read(b []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	go func() {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_ = c.Conn.Close() //nolint:errcheck // we tried, it failed, conn is broken, read will fail
		}
	}()

	return c.Conn.Read(b)
}

func (c clientTCPConnWithHardDeadline) Write(b []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	go func() {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_ = c.Conn.Close() //nolint:errcheck // we tried, it failed, conn is broken, read will fail
		}
	}()

	return c.Conn.Write(b)
}
