package mailbox

import (
	"context"
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

// Client manages the mailboxConn it holds and refreshes it on connection
// retries.
type Client struct {
	mailboxConn *SwitchConn

	ctx context.Context
}

// NewClient creates a new Client object which will handle the mailbox
// connection.
func NewClient(ctx context.Context, password []byte,
	localKey keychain.SingleKeyECDH, remoteKey *btcec.PublicKey,
	serverHost string) (*Client, error) {

	clientSwitch, err := NewSwitchConn(&SwitchConfig{
		ServerHost: serverHost,
		Password:   password,
		LocalKey:   localKey,
		RemoteKey:  remoteKey,
		NewProxyConn: func(ctx context.Context,
			sid [64]byte) (ProxyConn, error) {

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
		StopProxyConn: func(conn ProxyConn) error {
			return nil
		},
	})
	if err != nil {
		return nil, nil
	}

	return &Client{
		mailboxConn: clientSwitch,
		ctx:         ctx,
	}, nil
}

// Dial returns a net.Conn abstraction over the mailbox connection. Dial is
// called everytime grpc retries the connection. If this is the first
// connection, a new ClientConn will be created. Otherwise, the existing
// connection will just be refreshed.
func (c *Client) Dial(_ context.Context, _ string) (net.Conn, error) {
	log.Debugf("Client: Dialing...")

	err := c.mailboxConn.NextConn(c.ctx)
	if err != nil {
		return nil, &temporaryError{err}
	}

	return c.mailboxConn, nil
}
