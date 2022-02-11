package mailbox

import (
	"context"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

// Client manages the mailboxConn it holds and refreshes it on connection
// retries.
type Client struct {
	mailboxConn *ClientSwitch

	ctx context.Context
}

// NewClient creates a new Client object which will handle the mailbox
// connection.
func NewClient(ctx context.Context, password []byte,
	localKey keychain.SingleKeyECDH, remoteKey *btcec.PublicKey,
	serverHost string) (*Client, error) {

	clientSwitch, err := NewClientSwitch(
		serverHost, password, localKey, remoteKey,
	)
	if err != nil {
		return nil, err
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
