package mailbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestSpake2Mask tests the masking operation for SPAK2 to ensure that ti's
// properly reverseable.
func TestSpake2Mask(t *testing.T) {
	t.Parallel()

	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pub := priv.PubKey()

	pass := []byte("top secret")
	passHash := sha256.Sum256(pass)

	maskedPoint := ekeMask(pub, passHash[:])
	require.True(t, !maskedPoint.IsEqual(pub))

	unmaskedPoint := ekeUnmask(maskedPoint, passHash[:])
	require.True(t, unmaskedPoint.IsEqual(pub))
}

// TestXXHandshake tests that a client and server can successfully complete a
// Noise_XX pattern handshake and then use the encrypted connection to exchange
// messages afterwards.
func TestXXHandshake(t *testing.T) {
	// First, generate static keys for each party.
	pk1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	// Create a password that will be used to mask the first ephemeral key.
	pass := []byte("top secret")
	passHash := sha256.Sum256(pass)

	// The server will be initialised with auth data that it is expected to
	// send to the client during act 2 of the handshake.
	authData := []byte("authData")

	// Create a pipe and give one end to the client and one to the server
	// as the underlying transport.
	conn1, conn2 := newMockProxyConns()
	defer func() {
		conn1.Close()
		conn2.Close()
	}()

	// Create a server.
	server := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk1}, authData, passHash[:],
	)

	// Spin off the server's handshake process.
	var (
		serverConn    net.Conn
		serverErrChan = make(chan error)
	)
	go func() {
		var err error
		serverConn, _, err = server.ServerHandshake(conn1)
		serverErrChan <- err
	}()

	// Create a client.
	client := NewNoiseGrpcConn(
		&keychain.PrivKeyECDH{PrivKey: pk2}, nil, passHash[:],
	)

	// Start the client's handshake process.
	clientConn, _, err := client.ClientHandshake(
		context.Background(), "", conn2,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the server's handshake to complete or timeout.
	select {
	case err := <-serverErrChan:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(time.Second):
		t.Fatalf("handshake timeout")
	}

	// Ensure that any auth data was successfully received by the client.
	require.True(t, bytes.Equal(client.authData, authData))

	// Also check that both parties now have the other parties static key.
	require.True(t, client.remoteKey.IsEqual(pk1.PubKey()))
	require.True(t, server.remoteKey.IsEqual(pk2.PubKey()))

	// Check that messages can be sent between client and server normally
	// now.
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

// TestKKHandshake tests that a client and server Machine can successfully
// complete a Noise_KK pattern handshake.
func TestKKHandshake(t *testing.T) {
	// First, generate static keys for each party.
	pk1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	// Create a password that will be used to mask the first ephemeral key.
	pass := []byte("top secret")
	passHash := sha256.Sum256(pass)

	// The server will be initialised with auth data that it is expected to
	// send to the client during act 2 of the handshake.
	authData := []byte("authData")

	// Create a pipe and give one end to the client and one to the server
	// as the underlying transport.
	conn1, conn2 := newMockProxyConns()
	defer func() {
		conn1.Close()
		conn2.Close()
	}()

	// First, we'll initialize a new state machine for the server with our
	// static key, remote static key, passphrase, and also the
	// authentication data.
	server, err := NewBrontideMachine(
		false, KKPattern, &keychain.PrivKeyECDH{PrivKey: pk1},
		pk2.PubKey(), passHash[:], authData, HandshakeVersion,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Spin off the server's handshake process.
	var serverErrChan = make(chan error)
	go func() {
		err := server.DoHandshake(conn1)
		serverErrChan <- err
	}()

	// Create a client.
	client, err := NewBrontideMachine(
		true, KKPattern, &keychain.PrivKeyECDH{PrivKey: pk2},
		pk1.PubKey(), passHash[:], nil, HandshakeVersion,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Start the client's handshake process.
	if err := client.DoHandshake(conn2); err != nil {
		t.Fatal(err)
	}

	// Wait for the server's handshake to complete or timeout.
	select {
	case err := <-serverErrChan:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(time.Second):
		t.Fatalf("handshake timeout")
	}

	// Ensure that any auth data was successfully received by the client.
	require.True(t, bytes.Equal(client.receivedPayload, authData))

	// Also check that both parties now have the other parties static key.
	require.True(t, client.remoteStatic.IsEqual(pk1.PubKey()))
	require.True(t, server.remoteStatic.IsEqual(pk2.PubKey()))
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
