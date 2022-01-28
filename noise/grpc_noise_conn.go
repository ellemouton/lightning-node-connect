package noise

import (
	"context"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc/credentials"

	"net"
	"sync"
)

var (
	// lightningNodeConnectPrologue is the noise prologue that is used to
	// initialize the brontide noise handshake.
	lightningNodeConnectPrologue = []byte("lightning-node-connect")
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
	ProxyConn

	proxyConnMtx sync.RWMutex

	password []byte
	authData []byte

	localKey  keychain.SingleKeyECDH
	remoteKey *btcec.PublicKey

	nextMsg    []byte
	nextMsgMtx sync.Mutex

	noise *Machine
}

// NewNoiseGrpcConn creates a new noise connection using given local ECDH key.
// The auth data can be set for server connections and is sent as the payload
// to the client during the handshake.
func NewNoiseGrpcConn(localStaticKey keychain.SingleKeyECDH,
	remoteStaticKey *btcec.PublicKey, authData []byte,
	password []byte) *NoiseGrpcConn {

	return &NoiseGrpcConn{
		localKey:  localStaticKey,
		remoteKey: remoteStaticKey,
		authData:  authData,
		password:  password,
	}
}

// ClientHandshake implements the client side part of the noise connection
// handshake.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) ClientHandshake(_ context.Context, _ string,
	conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c.proxyConnMtx.Lock()
	defer c.proxyConnMtx.Unlock()

	log.Debugf("Starting client handshake")

	transportConn, ok := conn.(ProxyConn)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection type")
	}
	c.ProxyConn = transportConn

	var err error
	c.noise, err = NewMachine(
		true, c.localKey, c.remoteKey, c.password, c.authData,
		HandshakeVersion0,
	)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("Kicking off client handshake with client_key=%x",
		c.localKey.PubKey().SerializeCompressed())

	if err := c.noise.DoHandshake(c.ProxyConn); err != nil {
		return nil, nil, err
	}

	c.authData = c.noise.receivedPayload
	c.remoteKey = c.noise.rs

	log.Debugf("Completed client handshake with with server_key=%x",
		c.noise.rs.SerializeCompressed())

	log.Tracef("Client handshake completed")

	return c, NewAuthInfo(), nil
}

// ServerHandshake implements the server part of the noise connection handshake.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) ServerHandshake(conn net.Conn) (net.Conn,
	credentials.AuthInfo, error) {

	c.proxyConnMtx.Lock()
	defer c.proxyConnMtx.Unlock()

	log.Debugf("Starting server handshake")

	transportConn, ok := conn.(ProxyConn)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection type")
	}
	c.ProxyConn = transportConn

	// First, we'll initialize a new borntide machine with our static key,
	// passphrase, and also the macaroon authentication data.
	var err error
	c.noise, err = NewMachine(
		false, c.localKey, c.remoteKey, c.password, c.authData,
		HandshakeVersion0,
	)
	if err != nil {
		return nil, nil, err
	}

	if err := c.noise.DoHandshake(c.ProxyConn); err != nil {
		return nil, nil, err
	}

	c.authData = c.noise.receivedPayload
	c.remoteKey = c.noise.rs

	log.Debugf("Finished server handshake, client_key=%x",
		c.noise.rs.SerializeCompressed())

	return c, NewAuthInfo(), nil
}

// Read tries to read an encrypted data message from the underlying control
// connection and then tries to decrypt it.
//
// NOTE: This is part of the net.Conn interface.
func (c *NoiseGrpcConn) Read(b []byte) (n int, err error) {
	c.proxyConnMtx.RLock()
	defer c.proxyConnMtx.RUnlock()

	c.nextMsgMtx.Lock()
	defer c.nextMsgMtx.Unlock()

	// The last read was incomplete, return the few bytes that didn't fit.
	if len(c.nextMsg) > 0 {
		msgLen := len(c.nextMsg)
		copy(b, c.nextMsg)

		c.nextMsg = nil
		return msgLen, nil
	}

	requestBytes, err := c.noise.ReadMessage(c.ProxyConn)
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
	c.proxyConnMtx.RLock()
	defer c.proxyConnMtx.RUnlock()

	err := c.noise.WriteMessage(b)
	if err != nil {
		return 0, err
	}

	return c.noise.Flush(c.ProxyConn)
}

// LocalAddr returns the local address of this connection.
//
// NOTE: This is part of the Conn interface.
func (c *NoiseGrpcConn) LocalAddr() net.Addr {
	c.proxyConnMtx.RLock()
	defer c.proxyConnMtx.RUnlock()

	if c.ProxyConn == nil {
		return &NoiseAddr{PubKey: c.localKey.PubKey()}
	}

	return &NoiseAddr{
		PubKey: c.localKey.PubKey(),
		Server: c.ProxyConn.LocalAddr().String(),
	}
}

// RemoteAddr returns the remote address of this connection.
//
// NOTE: This is part of the Conn interface.
func (c *NoiseGrpcConn) RemoteAddr() net.Addr {
	c.proxyConnMtx.RLock()
	defer c.proxyConnMtx.RUnlock()

	if c.ProxyConn == nil {
		return &NoiseAddr{PubKey: c.remoteKey}
	}

	return &NoiseAddr{
		PubKey: c.remoteKey,
		Server: c.ProxyConn.RemoteAddr().String(),
	}
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

// Clone makes a copy of this TransportCredentials.
//
// NOTE: This is part of the credentials.TransportCredentials interface.
func (c *NoiseGrpcConn) Clone() credentials.TransportCredentials {
	c.proxyConnMtx.RLock()
	defer c.proxyConnMtx.RUnlock()

	return &NoiseGrpcConn{
		ProxyConn: c.ProxyConn,
		authData:  c.authData,
		localKey:  c.localKey,
		remoteKey: c.remoteKey,
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
