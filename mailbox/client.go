package mailbox

import (
	"context"
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

// Client manages the switchConn it holds and refreshes it on connection
// retries.
type Client struct {
	switchConfig *SwitchConfig
	switchConn   *SwitchConn

	ctx context.Context
	sid [64]byte
}

// NewClient creates a new Client object which will handle the mailbox
// connection.
func NewClient(ctx context.Context, password []byte,
	localKey keychain.SingleKeyECDH, remoteKey *btcec.PublicKey,
	serverHost string) (*Client, error) {

	return &Client{
		ctx: ctx,
		switchConfig: &SwitchConfig{
			ServerHost: serverHost,
			Password:   password,
			RemoteKey:  remoteKey,
			LocalKey:   localKey,
			NewProxyConn: func(sid [64]byte) (ProxyConn, error) {
				return NewClientConn(ctx, sid, serverHost)
			},
			RefreshProxyConn: func(conn ProxyConn) (ProxyConn, error) {
				clientConn, ok := conn.(*ClientConn)
				if !ok {
					return nil, fmt.Errorf("conn not of type " +
						"ClientConn")
				}

				return RefreshClientConn(clientConn)
			},
		},
	}, nil
}

// Dial returns a net.Conn abstraction over the mailbox connection. Dial is
// called everytime grpc retries the connection. If this is the first
// connection, a new ClientConn will be created. Otherwise, the existing
// connection will just be refreshed.
func (c *Client) Dial(_ context.Context, _ string) (net.Conn, error) {

	// If there is currently an active connection, block here until the
	// previous connection as been closed.
	if c.switchConn != nil {
		log.Debugf("Dial: have existing mailbox connection, waiting")
		<-c.switchConn.Done()
		log.Debugf("Dial: done with existing conn")
	}

	log.Debugf("Client: Dialing...")
	if c.switchConn == nil {
		switchConn, err := NewSwitchConn(c.switchConfig)
		if err != nil {
			if err := switchConn.Close(); err != nil {
				return nil, &temporaryError{err}
			}
			return nil, &temporaryError{err}
		}
		c.switchConn = switchConn
	} else {
		switchConn, err := RefreshSwitchConn(c.switchConn)
		if err != nil {
			if err := switchConn.Close(); err != nil {
				return nil, &temporaryError{err}
			}
			return nil, &temporaryError{err}
		}
		c.switchConn = switchConn
	}

	return c.switchConn, nil
}
