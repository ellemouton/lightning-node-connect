package noise

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/lightninglabs/lightning-node-connect/gbn"

	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"

	"github.com/btcsuite/btcd/btcec"

	"github.com/lightningnetwork/lnd/keychain"

	"github.com/stretchr/testify/require"
)

func TestXXHandshake(t *testing.T) {
	logWriter := build.NewRotatingLogWriter()
	interceptor, err := signal.Intercept()
	lnd.AddSubLogger(logWriter, Subsystem, interceptor, UseLogger)
	lnd.AddSubLogger(logWriter, gbn.Subsystem, interceptor, gbn.UseLogger)

	pk1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pass := []byte("top secret")
	passHash := sha256.Sum256(pass)

	authData := []byte("authData")

	server := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk1}, nil, authData, passHash[:],
	)

	client := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk2}, nil, nil, passHash[:],
	)

	conn1, conn2 := newMockProxyConns()
	defer func() {
		conn1.Close()
		conn2.Close()
	}()

	var (
		serverConn net.Conn
	)
	serverErrChan := make(chan error)
	go func() {
		var err error
		serverConn, _, err = server.ServerHandshake(
			conn1,
		)
		serverErrChan <- err
	}()

	clientConn, _, err := client.ClientHandshake(
		context.Background(), "", conn2,
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-serverErrChan:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(time.Second):
		t.Fatalf("handshake timeout")
	}

	// Ensure that any auth data was successfully received
	// by the client.
	require.True(t, bytes.Equal(client.authData, authData))

	// Also check that both parties now have the other parties static key.
	require.True(t, client.remoteKey.IsEqual(pk1.PubKey()))
	require.True(t, server.remoteKey.IsEqual(pk2.PubKey()))

	// Check that messages can be sent between client and
	// server normally now.
	testMessage := []byte("test message")
	go func() {
		_, err := clientConn.Write(testMessage)
		require.NoError(t, err)
	}()

	recvBuffer := make([]byte, len(testMessage))
	_, err = serverConn.Read(recvBuffer)
	require.NoError(t, err)
	require.True(t, bytes.Equal(recvBuffer, testMessage))
}

func TestKKHandshake(t *testing.T) {
	pk1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pass := []byte("top secret")
	passHash := sha256.Sum256(pass)

	authData := []byte("authData")

	server := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk1}, pk2.PubKey(),
		authData, passHash[:],
	)

	client := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk2}, pk1.PubKey(), nil,
		passHash[:],
	)

	conn1, conn2 := newMockProxyConns()
	defer func() {
		conn1.Close()
		conn2.Close()
	}()

	var (
		serverConn net.Conn
	)
	serverErrChan := make(chan error)
	go func() {
		var err error
		serverConn, _, err = server.ServerHandshake(
			conn1,
		)
		serverErrChan <- err
	}()

	clientConn, _, err := client.ClientHandshake(
		context.Background(), "", conn2,
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-serverErrChan:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(time.Second):
		t.Fatalf("handshake timeout")
	}

	// Ensure that any auth data was successfully received
	// by the client.
	require.True(t, bytes.Equal(client.authData, authData))

	// Check that messages can be sent between client and
	// server normally now.
	testMessage := []byte("test message")
	go func() {
		_, err := clientConn.Write(testMessage)
		require.NoError(t, err)
	}()

	recvBuffer := make([]byte, len(testMessage))
	_, err = serverConn.Read(recvBuffer)
	require.NoError(t, err)
	require.True(t, bytes.Equal(recvBuffer, testMessage))
}

var _ ProxyConn = (*mockProxyConn)(nil)

type mockProxyConn struct {
	net.Conn
}

func (m *mockProxyConn) ReceiveControlMsg(_ ControlMsg) error {
	return nil
}

func (m *mockProxyConn) SendControlMsg(_ ControlMsg) error {
	return nil
}

func newMockProxyConns() (*mockProxyConn, *mockProxyConn) {
	c1, c2 := net.Pipe()
	return &mockProxyConn{c1}, &mockProxyConn{c2}
}
