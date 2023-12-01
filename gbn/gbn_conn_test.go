package gbn

import (
	"bytes"
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormal(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	server, client, cleanup := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanup()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	go func() {
		err := server.Send(payload1)
		require.NoError(t, err)

		err = server.Send(payload2)
		require.NoError(t, err)
	}()

	msg, err := client.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = client.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

// TestServerHandshakeTimeout ensures that the SetRecvTimout properly exits out
// of the Recv function if the timout has passed before receiving anything.
// This is useful in the case of a handshake on the layer above GBN. The test
// does the following: We kick off a handshake but we ensure that the clients
// SYNACK message delays enough for the server to time out the handshake and
// start again by waiting for SYN. The client, however, will think the handshake
// has completed and so will go into normal message sending operation mode and
// so will call Recv or Send which will hang indefinitely unless we set a
// timeout.
func TestServerHandshakeTimeout(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	// Client Read
	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// Server write
	s1Write := func(ctx context.Context, b []byte) error { //nolint:unparam
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	// Server Read
	var (
		serverReadCount = 1
		countMu         sync.Mutex
	)
	s2Read := func(ctx context.Context) ([]byte, error) { //nolint:unparam
		countMu.Lock()
		defer func() {
			serverReadCount++
			countMu.Unlock()
		}()

		select {
		case val := <-s2Chan:
			// Let the client SYNACK message delay for a bit in
			// order to ensure that the server times it out.
			if serverReadCount == 2 {
				time.Sleep(defaultHandshakeTimeout * 2)
			}

			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// Client write
	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	var (
		server GBN
		wg     sync.WaitGroup
	)
	defer func() {
		if server != nil {
			server.Close()
		}
	}()

	payload1 := []byte("payload 1")

	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		server, err = NewServerConn(ctx, s1Write, s2Read)
		require.NoError(t, err)

		err = server.Send(payload1)
		require.NoError(t, err)
	}()

	// Give the server time to be ready for the handshake
	time.Sleep(time.Millisecond * 200)

	client, err := NewClientConn(ctx, 10, s2Write, s1Read)
	require.NoError(t, err)
	defer client.Close()

	client.SetRecvTimeout(defaultHandshakeTimeout)

	_, err = client.Recv()
	require.ErrorIs(t, err, errRecvTimeout)

	cancel()
	wg.Wait()

}

func TestDroppedMessage(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	var (
		count   int
		countMu sync.Mutex
	)
	s1Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		// Drop the first message (after handshake)
		if count == 2 {
			return nil
		}

		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)
	}()

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

func TestDroppedACKs(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	var (
		count   int
		countMu sync.Mutex
		n       uint8 = 2
	)
	s2Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		// Drop the first n messages (after handshake)
		if count > 2 && count < int(n+2) {
			return nil
		}

		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, n, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")
	payload3 := []byte("payload 3")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)

		err = p1.Send(payload3)
		require.NoError(t, err)
	}()

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload3))
}

func TestReceiveDuplicateMessages(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// duplicate messages (not including handshake)
	var (
		count   int
		countMu sync.Mutex
	)
	s1Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		s1Chan <- b

		if count < 1 {
			return nil
		}
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)
	}()

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

func TestReceiveDuplicateDataAndACKs(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// duplicate messages (not including handshake)
	var (
		count   int
		countMu sync.Mutex
	)
	s1Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		s1Chan <- b

		if count < 1 {
			return nil
		}
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// duplicate messages (not including handshake)
	var (
		count2   int
		count2Mu sync.Mutex
	)
	s2Write := func(ctx context.Context, b []byte) error {
		count2Mu.Lock()
		defer func() {
			count2++
			count2Mu.Unlock()
		}()

		s2Chan <- b

		if count2 < 2 {
			return nil
		}

		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)
	}()

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

func TestBidirectional(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")
	payload3 := []byte("payload 3")
	payload4 := []byte("payload 4")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)
	}()

	go func() {
		err := p2.Send(payload3)
		require.NoError(t, err)

		err = p2.Send(payload4)
		require.NoError(t, err)
	}()

	msg, err := p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload3))

	msg, err = p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload4))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

func TestSendNBeforeNeedingAck(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	err := p1.Send(payload1)
	require.NoError(t, err)

	err = p1.Send(payload2)
	require.NoError(t, err)

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))
}

func TestDropFirstNPackets(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	var (
		n       uint8 = 3
		count   uint8
		countMu sync.Mutex
	)
	s1Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		// drop first non-handshake packet
		if count > 0 && count < n+1 {
			return nil
		}

		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, n, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")
	payload3 := []byte("payload 3")

	err := p1.Send(payload1)
	require.NoError(t, err)

	err = p1.Send(payload2)
	require.NoError(t, err)

	err = p1.Send(payload3)
	require.NoError(t, err)

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload3))
}

func TestBidirectional2(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("client hello")
	payload2 := []byte("server hello")
	payload3 := []byte("client data 1")
	payload4 := []byte("client data 2")
	payload5 := []byte("client data 3")
	payload6 := []byte("server data 1")
	payload7 := []byte("server data 2")
	payload8 := []byte("client bye")
	payload9 := []byte("server bye")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Server
		msg, err := p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload1))

		err = p2.Send(payload2)
		require.NoError(t, err)

		msg, err = p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload3))

		msg, err = p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload4))

		msg, err = p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload5))

		err = p2.Send(payload6)
		require.NoError(t, err)

		err = p2.Send(payload7)
		require.NoError(t, err)

		msg, err = p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload8))

		err = p2.Send(payload9)
		require.NoError(t, err)
	}()

	// Client
	err := p1.Send(payload1)
	require.NoError(t, err)

	msg, err := p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))

	err = p1.Send(payload3)
	require.NoError(t, err)

	err = p1.Send(payload4)
	require.NoError(t, err)

	err = p1.Send(payload5)
	require.NoError(t, err)

	msg, err = p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload6))

	msg, err = p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload7))

	err = p1.Send(payload8)
	require.NoError(t, err)

	msg, err = p1.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload9))

	wg.Wait()
}

func TestSendingIsNonBlockingUpToN(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	// drop every 3rd packet (after handshake)
	var (
		count   int
		countMu sync.Mutex
	)
	s1Write := func(ctx context.Context, b []byte) error {
		countMu.Lock()
		defer func() {
			count++
			countMu.Unlock()
		}()

		if count != 0 && count%3 == 0 {
			return nil
		}

		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanUp := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanUp()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")
	payload3 := []byte("payload 3")
	payload4 := []byte("payload 4")

	go func() {
		err := p1.Send(payload1)
		require.NoError(t, err)

		err = p1.Send(payload2)
		require.NoError(t, err)

		msg, err := p1.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload3))

		err = p1.Send(payload4)
		require.NoError(t, err)
	}()

	err := p2.Send(payload3)
	require.NoError(t, err)

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload2))

	msg, err = p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload4))
}

func TestSendingLargeNumberOfMessages(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanup := setUpClientServerConns(
		t, 100, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanup()

	payload1 := []byte("payload 1")
	payload2 := []byte("payload 2")

	done := make(chan struct{})
	go func() {
		for i := 0; i <= 10000; i++ {
			err := p1.Send(payload1)
			require.NoError(t, err)

			msg, err := p1.Recv()
			require.NoError(t, err)
			require.True(t, bytes.Equal(msg, payload2))
		}
		close(done)
	}()

	for i := 0; i <= 10000; i++ {
		err := p2.Send(payload2)
		require.NoError(t, err)

		msg, err := p2.Recv()
		require.NoError(t, err)
		require.True(t, bytes.Equal(msg, payload1))
	}
	<-done
}

func TestResendAfterTimeout(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	p1, p2, cleanup := setUpClientServerConns(
		t, 100, s1Read, s2Read, s2Write, s1Write,
	)
	defer cleanup()

	payload1 := []byte("payload 1")

	err := p1.Send(payload1)
	require.NoError(t, err)

	msg, err := p2.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))
}

func TestPayloadSplitting(t *testing.T) {
	t.Parallel()

	s1Chan := make(chan []byte, 10)
	s2Chan := make(chan []byte, 10)

	s1Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s1Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s1Write := func(ctx context.Context, b []byte) error {
		select {
		case s1Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	s2Read := func(ctx context.Context) ([]byte, error) {
		select {
		case val := <-s2Chan:
			return val, nil
		case <-ctx.Done():
		}
		return nil, nil
	}

	s2Write := func(ctx context.Context, b []byte) error {
		select {
		case s2Chan <- b:
			return nil
		case <-ctx.Done():
		}
		return nil
	}

	maxPayloadSize := 1000
	payload1 := make([]byte, 4000)
	rand.Read(payload1)

	server, client, cleanup := setUpClientServerConns(
		t, 2, s1Read, s2Read, s2Write, s1Write,
		WithMaxSendSize(maxPayloadSize),
	)
	defer cleanup()

	go func() {
		err := server.Send(payload1)
		require.NoError(t, err)
	}()

	msg, err := client.Recv()
	require.NoError(t, err)
	require.True(t, bytes.Equal(msg, payload1))
}

func setUpClientServerConns(t *testing.T, n uint8,
	cRead, sRead func(ctx context.Context) ([]byte, error),
	cWrite, sWrite func(ctx context.Context, b []byte) error,
	opts ...Option) (GBN, GBN, func()) {

	t.Helper()

	var (
		server GBN
		err    error
		wg     sync.WaitGroup
	)

	ctx := context.Background()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		server, err = NewServerConn(ctx, sWrite, sRead, opts...)
		require.NoError(t, err)
	}()

	// Give the server time to be ready for the handshake
	time.Sleep(time.Millisecond * 200)

	client, err := NewClientConn(ctx, n, cWrite, cRead, opts...)
	require.NoError(t, err)

	wg.Wait()

	return server, client, func() {
		client.Close()
		server.Close()
	}
}
