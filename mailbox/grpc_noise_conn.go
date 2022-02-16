package mailbox

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc/credentials"
)

var _ credentials.TransportCredentials = (*NoiseGrpcConn)(nil)
var _ credentials.PerRPCCredentials = (*NoiseGrpcConn)(nil)

const (
	defaultGrpcWriteBufSize = 32 * 1024
)

// NoiseGrpcConn is a type that implements the credentials.TransportCredentials
// interface and can therefore be used as a replacement of the default TLS
// implementation that's used by HTTP/2.
type NoiseGrpcConn struct {
	*SwitchConn

	switchConnMtx sync.RWMutex

	password []byte
	authData []byte

	localKey  keychain.SingleKeyECDH
	remoteKey *btcec.PublicKey

	nextMsg    []byte
	nextMsgMtx sync.Mutex

	noise *Machine

	minHandshakeVersion byte
	maxHandshakeVersion byte
}

// NewNoiseGrpcConn creates a new noise connection using given local ECDH key.
// The auth data can be set for server connections and is sent as the payload
// to the client during the handshake.
func NewNoiseGrpcConn(localKey keychain.SingleKeyECDH,
	remoteKey *btcec.PublicKey, authData []byte, password []byte,
	options ...func(conn *NoiseGrpcConn)) *NoiseGrpcConn {

	conn := &NoiseGrpcConn{
		localKey:            localKey,
		remoteKey:           remoteKey,
		authData:            authData,
		password:            password,
		minHandshakeVersion: MinHandshakeVersion,
		maxHandshakeVersion: MaxHandshakeVersion,
	}

	if remoteKey != nil && conn.minHandshakeVersion < HandshakeVersion2 {
		conn.minHandshakeVersion = HandshakeVersion2
	}

	for _, opt := range options {
		opt(conn)
	}

	return conn
}

// WithMinHandshakeVersion is a functional option used to set the minimum
// handshake version supported.
func WithMinHandshakeVersion(version byte) func(*NoiseGrpcConn) {
	return func(conn *NoiseGrpcConn) {
		conn.minHandshakeVersion = version
	}
}

// WithMaxHandshakeVersion is a functional option used to set the maximum
// handshake version supported.
func WithMaxHandshakeVersion(version byte) func(*NoiseGrpcConn) {
	return func(conn *NoiseGrpcConn) {
		conn.maxHandshakeVersion = version
	}
}

// Read tries to read an encrypted data message from the underlying control
// connection and then tries to decrypt it.
//
// NOTE: This is part of the net.Conn interface.
func (c *NoiseGrpcConn) Read(b []byte) (n int, err error) {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	c.nextMsgMtx.Lock()
	defer c.nextMsgMtx.Unlock()

	// The last read was incomplete, return the few bytes that didn't fit.
	if len(c.nextMsg) > 0 {
		msgLen := len(c.nextMsg)
		copy(b, c.nextMsg)

		c.nextMsg = nil
		return msgLen, nil
	}

	requestBytes, err := c.noise.ReadMessage(c.SwitchConn)
	if err != nil {
		return 0, fmt.Errorf("error decrypting payload: %v", err)
	}

	// Do we need to read this message in two parts? We cannot give the
	// gRPC layer above us more than the default read buffer size of 32k
	// bytes at a time.
	if len(requestBytes) > defaultGrpcWriteBufSize {
		nextMsgLen := len(requestBytes) - defaultGrpcWriteBufSize
		c.nextMsg = make([]byte, nextMsgLen)

		copy(c.nextMsg[0:nextMsgLen], requestBytes[defaultGrpcWriteBufSize:])

		copy(b, requestBytes[0:defaultGrpcWriteBufSize])
		return defaultGrpcWriteBufSize, nil
	}

	copy(b, requestBytes)
	return len(requestBytes), nil
}

// Write encrypts the given application level payload and sends it as a data
// message over the underlying control connection.
//
// NOTE: This is part of the net.Conn interface.
func (c *NoiseGrpcConn) Write(b []byte) (int, error) {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	err := c.noise.WriteMessage(b)
	if err != nil {
		return 0, err
	}

	return c.noise.Flush(c.SwitchConn)
}

// LocalAddr returns the local address of this connection.
//
// NOTE: This is part of the Conn interface.
func (c *NoiseGrpcConn) LocalAddr() net.Addr {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	if c.SwitchConn == nil {
		return &NoiseAddr{PubKey: c.localKey.PubKey()}
	}

	return &NoiseAddr{
		PubKey: c.localKey.PubKey(),
		Server: c.SwitchConn.LocalAddr().String(),
	}
}

// RemoteAddr returns the remote address of this connection.
//
// NOTE: This is part of the Conn interface.
func (c *NoiseGrpcConn) RemoteAddr() net.Addr {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	if c.SwitchConn == nil {
		return &NoiseAddr{PubKey: c.remoteKey}
	}

	return &NoiseAddr{
		PubKey: c.remoteKey,
		Server: c.SwitchConn.RemoteAddr().String(),
	}
}

// ClientHandshake implements the client side part of the noise connection
// handshake.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) ClientHandshake(_ context.Context, _ string,
	conn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	c.switchConnMtx.Lock()
	defer c.switchConnMtx.Unlock()

	log.Tracef("Starting client handshake")

	transportConn, ok := conn.(*SwitchConn)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection type: %T", conn)
	}
	c.SwitchConn = transportConn

	log.Debugf("Kicking off client handshake with client_key=%x",
		c.localKey.PubKey().SerializeCompressed())

	// We'll ensure that we get a response from the remote peer in a timely
	// manner. If they don't respond within 1s, then we'll kill the
	// connection.
	err := c.SwitchConn.SetReadDeadline(
		time.Now().Add(handshakeReadTimeout),
	)
	if err != nil {
		return nil, nil, err
	}

	// First, initialize a new noise machine with our static long term, and
	// password.
	if c.remoteKey == nil {
		fmt.Println("CLient: remote is nil, doing XX")
		var err error
		c.noise, err = NewBrontideMachine(&BrontideMachineConfig{
			Initiator:           true,
			HandshakePattern:    XXPattern,
			LocalStaticKey:      c.localKey,
			PAKEPassphrase:      c.password,
			MinHandshakeVersion: c.minHandshakeVersion,
			MaxHandshakeVersion: c.maxHandshakeVersion,
		})
		if err != nil {
			return nil, nil, err
		}

		if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
			return nil, nil, err
		}

		// TODO(elle): need to here ensure that the server has received
		// the last message before terminating the connection. Need to
		// build perhaps a blocking Send() option into GBN layer so it
		// only returns if all ACKs for that message have been received.
		time.Sleep(time.Second)

		if c.noise.version >= HandshakeVersion2 {
			fmt.Println("Client: XX done, now doing KK")
			// At this point, we'll also extract the auth data and
			// remote static key obtained during the handshake.
			c.remoteKey = c.noise.remoteStatic

			if err := c.SwitchConn.Switch(c.remoteKey); err != nil {
				fmt.Println("CLIENT EXITING HERE")
				return nil, nil, err
			}

			c.noise, err = NewBrontideMachine(
				&BrontideMachineConfig{
					Initiator:           true,
					HandshakePattern:    KKPattern,
					LocalStaticKey:      c.localKey,
					RemoteStaticKey:     c.remoteKey,
					MinHandshakeVersion: HandshakeVersion2, // TODO(elle): fix this
					MaxHandshakeVersion: c.maxHandshakeVersion,
				})
			if err != nil {
				fmt.Println("CLIENT EXITING HERE")
				return nil, nil, err
			}

			if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
				fmt.Println("CLIENT EXITING HERE")
				return nil, nil, err
			}
		}

	} else {
		fmt.Println("CLient: Remote is non nil, starting with KK")
		// At this point, we'll also extract the auth data and
		c.noise, err = NewBrontideMachine(
			&BrontideMachineConfig{
				Initiator:           true,
				HandshakePattern:    KKPattern,
				LocalStaticKey:      c.localKey,
				RemoteStaticKey:     c.remoteKey,
				MinHandshakeVersion: HandshakeVersion2, // TODO(elle): fix this
				MaxHandshakeVersion: c.maxHandshakeVersion,
			})
		if err != nil {
			return nil, nil, err
		}

		if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
			fmt.Println("CLIENT EXITING HERE")
			return nil, nil, err
		}
	}

	c.authData = c.noise.receivedPayload

	// We'll reset the deadline as it's no longer critical beyond the
	// initial handshake.
	err = c.SwitchConn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("Completed client handshake with with server_key=%x",
		c.noise.remoteStatic.SerializeCompressed())

	log.Tracef("Client handshake completed")

	return c, NewAuthInfo(), nil
}

// ServerHandshake implements the server part of the noise connection handshake.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) ServerHandshake(conn net.Conn) (net.Conn,
	credentials.AuthInfo, error) {

	log.Debugf("WAITING HERE")

	c.switchConnMtx.Lock()
	defer c.switchConnMtx.Unlock()

	log.Debugf("Starting server handshake")

	transportConn, ok := conn.(*SwitchConn)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection type")
	}
	c.SwitchConn = transportConn

	// We'll ensure that we get a response from the remote peer in a timely
	// manner. If they don't respond within 1s, then we'll kill the
	// connection.
	err := c.SwitchConn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	if err != nil {
		return nil, nil, err
	}

	if c.remoteKey == nil {
		fmt.Println("Server: remote is nil. Doing XX")
		// First, we'll initialize a new state machine with our static key,
		// remote static key, passphrase, and also the authentication data.
		var err error
		c.noise, err = NewBrontideMachine(&BrontideMachineConfig{
			Initiator:           false,
			HandshakePattern:    XXPattern,
			MinHandshakeVersion: c.minHandshakeVersion,
			MaxHandshakeVersion: c.maxHandshakeVersion,
			LocalStaticKey:      c.localKey,
			PAKEPassphrase:      c.password,
			AuthData:            c.authData,
		})
		if err != nil {
			fmt.Println("SERVER EXITING HERE 1")
			return nil, nil, err
		}

		if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
			fmt.Println("SERVER EXITING HERE 2")
			return nil, nil, err
		}

		if c.noise.version >= HandshakeVersion2 {
			fmt.Println("Server: XX is done. Now switching and doing KK")
			// At this point, we'll also extract the and remote
			// static key obtained during the handshake.
			c.remoteKey = c.noise.remoteStatic

			// SWITCH
			if err := c.SwitchConn.Switch(c.remoteKey); err != nil {
				fmt.Println("SERVER EXITING HERE 3")
				return nil, nil, err
			}

			c.noise, err = NewBrontideMachine(&BrontideMachineConfig{
				Initiator:           false,
				HandshakePattern:    KKPattern,
				MinHandshakeVersion: HandshakeVersion2,
				MaxHandshakeVersion: c.maxHandshakeVersion,
				LocalStaticKey:      c.localKey,
				RemoteStaticKey:     c.remoteKey,
				AuthData:            c.authData,
			})
			if err != nil {
				fmt.Println("SERVER EXITING HERE 4")
				return nil, nil, err
			}

			if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
				fmt.Println("SERVER EXITING HERE 5")
				return nil, nil, err
			}
		}
	} else {
		fmt.Println("Server: remote is non-nil. Doing KK")
		c.noise, err = NewBrontideMachine(&BrontideMachineConfig{
			Initiator:           false,
			HandshakePattern:    KKPattern,
			MinHandshakeVersion: HandshakeVersion2,
			MaxHandshakeVersion: c.maxHandshakeVersion,
			LocalStaticKey:      c.localKey,
			RemoteStaticKey:     c.remoteKey,
			AuthData:            c.authData,
		})
		if err != nil {
			fmt.Println("SERVER EXITING HERE 6")
			return nil, nil, err
		}

		if err := c.noise.DoHandshake(c.SwitchConn); err != nil {
			fmt.Printf("SERVER EXITING HERE 7 %v\n", err)
			return nil, nil, err
		}
	}

	// We'll reset the deadline as it's no longer critical beyond the
	// initial handshake.
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("Finished server handshake, client_key=%x",
		c.noise.remoteStatic.SerializeCompressed())

	return c, NewAuthInfo(), nil
}

// Info returns general information about the protocol that's being used for
// this connection.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		ProtocolVersion:  fmt.Sprintf("%d", ProtocolVersion),
		SecurityProtocol: ProtocolName,
		ServerName:       "lnd",
	}
}

// Close ensures that we hold a lock on the SwitchConn before calling close on
// it to ensure that the handshake functions don't use the SwitchConn at the
// same time.
//
// NOTE: This is part of the net.Conn interface.
func (c *NoiseGrpcConn) Close() error {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	return c.SwitchConn.Close()
}

// Clone makes a copy of this TransportCredentials.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) Clone() credentials.TransportCredentials {
	c.switchConnMtx.RLock()
	defer c.switchConnMtx.RUnlock()

	return &NoiseGrpcConn{
		SwitchConn: c.SwitchConn,
		authData:   c.authData,
		localKey:   c.localKey,
		remoteKey:  c.remoteKey,
	}
}

// OverrideServerName overrides the server name used to verify the hostname on
// the returned certificates from the server.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) OverrideServerName(_ string) error {
	return nil
}

// RequireTransportSecurity returns true if this connection type requires
// transport security.
//
// NOTE: This is part of the credentials.PerRPCCredentials interface.
func (c *NoiseGrpcConn) RequireTransportSecurity() bool {
	return true
}

// GetRequestMetadata returns the per RPC credentials encoded as gRPC metadata.
//
// NOTE: This is part of the credentials.PerRPCCredentials interface.
func (c *NoiseGrpcConn) GetRequestMetadata(_ context.Context,
	_ ...string) (map[string]string, error) {

	md := make(map[string]string)

	// The authentication data is just a string encoded representation of
	// HTTP header fields. So we can split by '\r\n' to get individual lines
	// and then by ': ' to get field name and field value.
	lines := strings.Split(string(c.authData), "\r\n")
	for _, line := range lines {
		parts := strings.Split(line, ": ")
		if len(parts) != 2 {
			continue
		}

		md[parts[0]] = parts[1]
	}
	return md, nil
}
