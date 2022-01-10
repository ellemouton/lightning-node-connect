package mailbox

import (
	"bytes"
	"crypto/sha256"
	"github.com/lightningnetwork/lnd/keychain"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
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

func TestHandshake(t *testing.T) {
	tests := []struct {
		name                 string
		serverMinVersion     byte
		serverCurrentVersion byte
		clientMinVersion     byte
		clientCurrentVersion byte
		expectClientErr      bool
		expectServerErr      bool
		authData             []byte
	}{
		{
			name:                 "server and client v0",
			serverMinVersion:     HandshakeVersion0,
			serverCurrentVersion: HandshakeVersion0,
			clientMinVersion:     HandshakeVersion0,
			clientCurrentVersion: HandshakeVersion0,
			authData:             []byte{0, 1, 2, 3},
		},
	}

	pk1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pk2, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewNoiseGrpcConn(
				&keychain.PrivKeyECDH{PrivKey: pk1},
				test.authData, pass,
				WithMinHandshakeVersion(test.serverMinVersion),
				WithCurrentHandshakeVersion(
					test.serverCurrentVersion,
				),
			)

			client := NewNoiseGrpcConn(
				&keychain.PrivKeyECDH{PrivKey: pk2}, nil, pass,
				WithMinHandshakeVersion(test.clientMinVersion),
				WithCurrentHandshakeVersion(
					test.clientCurrentVersion,
				),
			)

			conn1, conn2 := newMockProxyConns()
			defer func() {
				conn1.Close()
				conn2.Close()
			}()

			var (
				serverConn net.Conn
				err        error
			)
			serverErrChan := make(chan error)
			go func() {
				serverConn, _, err = server.ServerHandshake(
					conn1,
				)
				serverErrChan <- err
			}()

			clientConn, _, err := client.ClientHandshake(
				nil, "", conn2,
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
			require.True(
				t, bytes.Equal(client.authData, test.authData),
			)

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
		})
	}
}

var _ ProxyConn = (*mockProxyConn)(nil)

type mockProxyConn struct {
	net.Conn
}

func (m *mockProxyConn) ReceiveControlMsg(msg ControlMsg) error {
	return nil
}

func (m *mockProxyConn) SendControlMsg(msg ControlMsg) error {
	return nil
}

func newMockProxyConns() (*mockProxyConn, *mockProxyConn) {
	c1, c2 := net.Pipe()
	return &mockProxyConn{c1}, &mockProxyConn{c2}
}
