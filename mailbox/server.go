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
	mailboxConn *SwitchConn

	ctx context.Context

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

	s := &Server{}

	s.ctx, s.cancel = context.WithCancel(context.Background())

	serverSwitch, err := NewSwitchConn(s.ctx, &SwitchConfig{
		ServerHost: serverHost,
		Password:   password,
		LocalKey:   localKey,
		RemoteKey:  remoteKey,
		NewProxyConn: func(sid [64]byte) (ProxyConn, error) {
			return NewServerConn(
				s.ctx, serverHost, clientConn, sid,
			)
		},
		RefreshProxyConn: func(conn ProxyConn) (ProxyConn, error) {
			serverConn, ok := conn.(*ServerConn)
			if !ok {
				return nil, fmt.Errorf("conn not of type " +
					"ServerConn")
			}

			return RefreshServerConn(serverConn)
		},
		StopProxyConn: func(conn ProxyConn) error {
			serverConn, ok := conn.(*ServerConn)
			if !ok {
				return fmt.Errorf("conn not of type ServerConn")
			}

			return serverConn.Stop()
		},
	})
	if err != nil {
		return nil, err
	}

	s.mailboxConn = serverSwitch

	return s, nil
}

// Accept is part of the net.Listener interface. The gRPC server will call this
// function to get a new net.Conn object to use for communication and it will
// also call this function each time it returns in order to facilitate multiple
// concurrent grpc connections. In our use case, we require that only one
// connection is active at a time. Therefore we block on a select function until
// the previous mailboxConn has completed.
func (s *Server) Accept() (net.Conn, error) {
	select {
	case <-s.ctx.Done():
		return nil, io.EOF
	default:
	}

	err := s.mailboxConn.NextConn()
	if err != nil {
		return nil, &temporaryError{err}
	}

	return s.mailboxConn, nil
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

	if err := s.mailboxConn.Stop(); err != nil {
		log.Errorf("error closing mailboxConn %v", err)
	}

	s.cancel()
	return nil
}

func (s *Server) Addr() net.Addr {
	return s.mailboxConn.Addr()
}
