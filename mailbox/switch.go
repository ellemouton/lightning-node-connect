package mailbox

import (
	"context"
	"crypto/sha512"
	"io"
	"net"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightninglabs/lightning-node-connect/hashmailrpc"
	"github.com/lightningnetwork/lnd/keychain"
)

type Switch interface {
	NextConn(ctx context.Context) error
	Switch()
}

type ServerSwitch struct {
	serverAddr string
	client     hashmailrpc.HashMailClient

	localKey keychain.SingleKeyECDH

	sid   [64]byte
	sidMu sync.Mutex

	*ServerConn
}

var _ Switch = (*ServerSwitch)(nil)

func (s *ServerSwitch) NextConn(ctx context.Context) error {
	// If there is currently an active connection, block here until the
	// previous connection as been closed.
	if s.ServerConn != nil {
		log.Debugf("Accept: have existing mailbox connection, waiting")
		select {
		case <-ctx.Done():
			return io.EOF
		case <-s.ServerConn.Done():
			log.Debugf("Accept: done with existing conn")
		}
	}

	// If this is the first connection, we create a new ServerConn object.
	// otherwise, we just refresh the ServerConn.
	var (
		serverConn *ServerConn
		err        error
	)
	if s.ServerConn == nil {
		serverConn, err = NewServerConn(
			ctx, s.serverAddr, s.client, s.sid,
		)
		if err != nil {
			log.Errorf("couldn't create new server: %v", err)
			if err := serverConn.Close(); err != nil {
				return err
			}
			return err
		}
	} else {
		serverConn, err = RefreshServerConn(s.ServerConn)
		if err != nil {
			log.Errorf("couldn't refresh server: %v", err)
			if err := serverConn.Stop(); err != nil {
				return err
			}

			s.ServerConn = nil
			return err
		}
	}

	s.ServerConn = serverConn
	return nil
}

func (s *ServerSwitch) Addr() net.Addr {
	return &Addr{SID: s.sid, Server: s.serverAddr}
}

func (s *ServerSwitch) Switch() {
	//TODO implement me
	panic("implement me")
}

func (s *ServerSwitch) Stop() error {
	if s.ServerConn != nil {
		if err := s.ServerConn.Stop(); err != nil {
			return err
		}
	}

	return nil
}

func NewServerSwitch(addr string, client hashmailrpc.HashMailClient,
	password []byte, localKey keychain.SingleKeyECDH,
	remoteKey *btcec.PublicKey) (*ServerSwitch, error) {

	var (
		entropy = password
		err     error
	)
	if remoteKey != nil {
		entropy, err = ecdh(remoteKey, localKey)
		if err != nil {
			return nil, err
		}
	}

	return &ServerSwitch{
		serverAddr: addr,
		client:     client,
		localKey:   localKey,
		sid:        sha512.Sum512(entropy),
	}, nil
}

type ClientSwitch struct {
	serverHost string

	remoteKey *btcec.PublicKey
	sid       [64]byte
	sidMu     *sync.Mutex

	*ClientConn
}

func NewClientSwitch(addr string, password []byte,
	localKey keychain.SingleKeyECDH,
	remoteKey *btcec.PublicKey) (*ClientSwitch, error) {

	var (
		entropy = password
		err     error
	)
	if remoteKey != nil {
		entropy, err = ecdh(remoteKey, localKey)
		if err != nil {
			return nil, err
		}
	}

	return &ClientSwitch{
		serverHost: addr,
		remoteKey:  remoteKey,
		sid:        sha512.Sum512(entropy),
	}, nil
}

func (c *ClientSwitch) NextConn(ctx context.Context) error {
	// If there is currently an active connection, block here until the
	// previous connection as been closed.
	if c.ClientConn != nil {
		log.Debugf("Dial: have existing mailbox connection, waiting")
		<-c.ClientConn.Done()
		log.Debugf("Dial: done with existing conn")
	}

	var (
		clientConn *ClientConn
		err        error
	)
	if c.ClientConn == nil {
		clientConn, err = NewClientConn(ctx, c.sid, c.serverHost)
		if err != nil {
			if err := clientConn.Close(); err != nil {
				return err
			}
			return err
		}
	} else {
		clientConn, err = RefreshClientConn(ctx, c.ClientConn)
		if err != nil {
			if err := clientConn.Close(); err != nil {
				return err
			}
			return err
		}
	}

	c.ClientConn = clientConn
	return nil
}

func (c *ClientSwitch) Switch() {
	//TODO implement me
	panic("implement me")
}

var _ Switch = (*ClientSwitch)(nil)

func GetSID(sid [64]byte, serverToClient bool) [64]byte {
	if serverToClient {
		return sid
	}

	var clientToServerSID [64]byte
	copy(clientToServerSID[:], sid[:])
	clientToServerSID[63] ^= 0x01

	return clientToServerSID
}
