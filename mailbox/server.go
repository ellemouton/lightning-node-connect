package mailbox

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightninglabs/lightning-node-connect/hashmailrpc"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc"
)

var _ net.Listener = (*Server)(nil)

type Server struct {
	serverHost string

	client hashmailrpc.HashMailClient

	switchConfig *SwitchConfig
	switchConn   *SwitchConn

	password  []byte
	localKey  keychain.SingleKeyECDH
	remoteKey *btcec.PublicKey

	ctx context.Context

	quit   chan struct{}
	cancel func()
}

func NewServer(serverHost string, password []byte,
	localKey keychain.SingleKeyECDH, remoteKey *btcec.PublicKey,
	dialOpts ...grpc.DialOption) (*Server, error) {

	mailboxGrpcConn, err := grpc.Dial(serverHost, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC server: %v",
			err)
	}

	clientConn := hashmailrpc.NewHashMailClient(mailboxGrpcConn)

	s := &Server{
		serverHost: serverHost,
		client:     clientConn,
		password:   password,
		localKey:   localKey,
		remoteKey:  remoteKey,
		quit:       make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	switchConfig := &SwitchConfig{
		ServerHost: serverHost,
		Password:   password,
		LocalKey:   localKey,
		RemoteKey:  remoteKey,
		NewProxyConn: func(sid [64]byte) (ProxyConn, error) {
			return NewServerConn(s.ctx, serverHost, clientConn, sid)
		},
		RefreshProxyConn: func(conn ProxyConn) (ProxyConn, error) {
			serverConn, ok := conn.(*ServerConn)
			if !ok {
				return nil, fmt.Errorf("conn not of type " +
					"ServerConn")
			}

			return RefreshServerConn(serverConn)
		},
	}

	s.switchConfig = switchConfig

	return s, nil
}

// Accept is part of the net.Listener interface. The gRPC server will call this
// function to get a new net.Conn object to use for communication and it will
// also call this function each time it returns in order to facilitate multiple
// concurrent grpc connections. In our use case, we require that only one
// connection is active at a time. Therefore we block on a select function until
// the previous switchConn has completed.
func (s *Server) Accept() (net.Conn, error) {
	select {
	case <-s.ctx.Done():
		return nil, io.EOF
	default:
	}

	// If there is currently an active connection, block here until the
	// previous connection as been closed.
	if s.switchConn != nil {
		log.Debugf("Accept: have existing mailbox connection, waiting")
		select {
		case <-s.quit:
			return nil, io.EOF
		case <-s.switchConn.Done():
			log.Debugf("Accept: done with existing conn")
		}
	}

	// If this is the first connection, we create a new SwitchConn object.
	// otherwise, we just refresh the SwitchConn.
	var (
		switchConn *SwitchConn
		err        error
	)
	if s.switchConn == nil {
		switchConn, err = NewSwitchConn(s.switchConfig)
		if err != nil {
			log.Errorf("couldn't create new server switch: %v", err)
			if err := switchConn.Close(); err != nil {
				return nil, &temporaryError{err}
			}
			return nil, &temporaryError{err}
		}

	} else {
		switchConn, err = RefreshSwitchConn(s.switchConn)
		if err != nil {
			log.Errorf("couldn't refresh server switch: %v", err)
			if err := switchConn.Close(); err != nil {
				return nil, &temporaryError{err}
			}

			s.switchConn = nil
			return nil, &temporaryError{err}
		}
	}

	s.switchConn = switchConn

	return s.switchConn, nil
}

// temporaryError implements the Temporary interface that grpc uses to decide
// if it should retry and reenter Accept instead of closing the server all
// together.
type temporaryError struct {
	error
}

// Temporary ensures that temporaryError satisfies the Temporary interface that
// grpc requires a returned error from the Accept function to implement so that
// it can determine if it should try again or completely shutdown the server.
func (e *temporaryError) Temporary() bool {
	return true
}

func (s *Server) Close() error {
	log.Debugf("conn being closed")

	close(s.quit)

	if s.switchConn != nil {
		if err := s.switchConn.Close(); err != nil {
			log.Errorf("error closing switchConn %v", err)
		}
	}

	s.cancel()
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.switchConn != nil {
		return s.switchConn.Addr()
	}

	return &Addr{
		SID:    [64]byte{},
		Server: s.serverHost,
	}
}

func GetSID(sid [64]byte, serverToClient bool) [64]byte {
	if serverToClient {
		return sid
	}

	var clientToServerSID [64]byte
	copy(clientToServerSID[:], sid[:])
	clientToServerSID[63] ^= 0x01

	return clientToServerSID
}
