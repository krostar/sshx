package sshx

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_clientTCPConnWithSoftDeadline_Read(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithSoftDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("SetReadDeadline", mock.MatchedBy(func(d time.Time) bool {
			return d.After(time.Now()) && d.Before(time.Now().Add(conn.timeout+time.Minute))
		})).Return(nil).Once()
		mockedConn.On("Read", providedB).Return(expectedN, errForTest).Once()

		n, err := conn.Read(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})

	t.Run("set deadline failed", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })
		mockedConn.On("SetReadDeadline", mock.Anything).Return(errForTest).Once()

		conn := &clientTCPConnWithSoftDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}
		n, err := conn.Read([]byte("hello"))
		assert.Check(t, n == 0)
		assert.Assert(t, cmp.ErrorContains(err, "unable to set read deadline"))
		assert.ErrorIs(t, err, errForTest)
	})
}

func Test_clientTCPConnWithSoftDeadline_Write(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithSoftDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("SetWriteDeadline", mock.MatchedBy(func(d time.Time) bool {
			return d.After(time.Now()) && d.Before(time.Now().Add(conn.timeout+time.Minute))
		})).Return(nil).Once()
		mockedConn.On("Write", providedB).Return(expectedN, errForTest).Once()

		n, err := conn.Write(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})

	t.Run("set deadline failed", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithSoftDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}

		mockedConn.On("SetWriteDeadline", mock.Anything).Return(errForTest).Once()

		n, err := conn.Write([]byte("hello"))
		assert.Check(t, n == 0)
		assert.Assert(t, cmp.ErrorContains(err, "unable to set write deadline"))
		assert.ErrorIs(t, err, errForTest)
	})
}

func Test_clientTCPConnWithHardDeadline_Read(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithHardDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("Read", providedB).Return(expectedN, errForTest).Once()

		n, err := conn.Read(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})

	t.Run("context deadline expired", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithHardDeadline{
			Conn:    mockedConn,
			timeout: time.Millisecond * 100,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("Read", providedB).Run(func(mock.Arguments) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			<-ctx.Done()
		}).Return(expectedN, errForTest).Once()
		mockedConn.On("Close").Return(nil).Once()

		n, err := conn.Read(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})
}

func Test_clientTCPConnWithHardDeadline_Write(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithHardDeadline{
			Conn:    mockedConn,
			timeout: time.Hour,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("Write", providedB).Return(expectedN, errForTest).Once()

		n, err := conn.Write(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})

	t.Run("context deadline expired", func(t *testing.T) {
		mockedConn := new(netConnMock)
		mockedConn.Test(t)
		t.Cleanup(func() { mockedConn.AssertExpectations(t) })

		conn := &clientTCPConnWithHardDeadline{
			Conn:    mockedConn,
			timeout: time.Millisecond * 100,
		}

		providedB := []byte("hello")
		expectedN := 4

		mockedConn.On("Write", providedB).Run(func(mock.Arguments) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			<-ctx.Done()
		}).Return(expectedN, errForTest).Once()
		mockedConn.On("Close").Return(nil).Once()

		n, err := conn.Write(providedB)
		assert.Check(t, cmp.Equal(expectedN, n))
		assert.ErrorIs(t, err, errForTest)
	})
}

type netConnMock struct{ mock.Mock }

func (c *netConnMock) Read(b []byte) (int, error) {
	args := c.Called(b)
	return args.Int(0), args.Error(1)
}

func (c *netConnMock) Write(b []byte) (int, error) {
	args := c.Called(b)
	return args.Int(0), args.Error(1)
}

func (c *netConnMock) Close() error {
	return c.Called().Error(0)
}

func (c *netConnMock) LocalAddr() net.Addr {
	args := c.Called()

	var addr net.Addr
	if arg := args.Get(0); args != nil {
		addr = arg.(net.Addr)
	}

	return addr
}

func (c *netConnMock) RemoteAddr() net.Addr {
	args := c.Called()

	var addr net.Addr
	if arg := args.Get(0); args != nil {
		addr = arg.(net.Addr)
	}

	return addr
}

func (c *netConnMock) SetDeadline(t time.Time) error {
	return c.Called(t).Error(0)
}

func (c *netConnMock) SetReadDeadline(t time.Time) error {
	return c.Called(t).Error(0)
}

func (c *netConnMock) SetWriteDeadline(t time.Time) error {
	return c.Called(t).Error(0)
}
